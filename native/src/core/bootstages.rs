use crate::consts::{APP_PACKAGE_NAME, BBPATH, DATABIN, MODULEROOT, SECURE_DIR};
use crate::daemon::MagiskD;
use crate::ffi::{
    DbEntryKey, RequestCode, check_key_combo, exec_common_scripts, exec_module_scripts,
    get_magisk_tmp, initialize_denylist,
};
use crate::logging::setup_logfile;
use crate::module::disable_modules;
use crate::mount::{clean_mounts, setup_preinit_dir};
use crate::resetprop::get_prop;
use crate::selinux::restorecon;
use base::const_format::concatcp;
use base::{BufReadExt, FsPathBuilder, ResultExt, cstr, error, info};
use bitflags::bitflags;
use nix::fcntl::OFlag;
use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;

bitflags! {
    #[derive(Default)]
    pub struct BootState : u32 {
        const PostFsDataDone = 1 << 0;
        const LateStartDone = 1 << 1;
        const BootComplete = 1 << 2;
        const SafeMode = 1 << 3;
    }
}

impl MagiskD {
    fn setup_magisk_env(&self) -> bool {
        info!("* Initializing Magisk environment");

        let mut buf = cstr::buf::default();

        let app_bin_dir = buf
            .append_path(self.app_data_dir())
            .append_path("0")
            .append_path(APP_PACKAGE_NAME)
            .append_path("install");

        // Alternative binaries paths
        let alt_bin_dirs = &[
            cstr!("/cache/data_adb/magisk"),
            cstr!("/data/magisk"),
            app_bin_dir,
        ];
        for dir in alt_bin_dirs {
            if dir.exists() {
                cstr!(DATABIN).remove_all().ok();
                dir.copy_to(cstr!(DATABIN)).ok();
                dir.remove_all().ok();
            }
        }
        cstr!("/cache/data_adb").remove_all().ok();

        // Directories in /data/adb
        cstr!(SECURE_DIR).follow_link().chmod(0o700).log_ok();
        cstr!(DATABIN).mkdir(0o755).log_ok();
        cstr!(MODULEROOT).mkdir(0o755).log_ok();
        cstr!(concatcp!(SECURE_DIR, "/post-fs-data.d"))
            .mkdir(0o755)
            .log_ok();
        cstr!(concatcp!(SECURE_DIR, "/service.d"))
            .mkdir(0o755)
            .log_ok();
        restorecon();

        let busybox = cstr!(concatcp!(DATABIN, "/busybox"));
        if !busybox.exists() {
            return false;
        }

        let tmp_bb = buf.append_path(get_magisk_tmp()).append_path(BBPATH);
        tmp_bb.mkdirs(0o755).ok();
        tmp_bb.append_path("busybox");
        tmp_bb.follow_link().chmod(0o755).log_ok();
        busybox.copy_to(tmp_bb).ok();

        // Install busybox applets
        Command::new(&tmp_bb)
            .arg("--install")
            .arg("-s")
            .arg(tmp_bb.parent_dir().unwrap())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .log_ok();

        // magisk32 and magiskpolicy are not installed into ramdisk and has to be copied
        // from data to magisk tmp
        let magisk32 = cstr!(concatcp!(DATABIN, "/magisk32"));
        if magisk32.exists() {
            let tmp = buf.append_path(get_magisk_tmp()).append_path("magisk32");
            magisk32.copy_to(tmp).log_ok();
        }
        let magiskpolicy = cstr!(concatcp!(DATABIN, "/magiskpolicy"));
        if magiskpolicy.exists() {
            let tmp = buf
                .append_path(get_magisk_tmp())
                .append_path("magiskpolicy");
            magiskpolicy.copy_to(tmp).log_ok();
        }

        true
    }

    fn post_fs_data(&self) -> bool {
        setup_logfile();
        info!("** post-fs-data mode running");

        self.preserve_stub_apk();

        // Check secure dir
        let secure_dir = cstr!(SECURE_DIR);
        if !secure_dir.exists() {
            if self.sdk_int < 24 {
                secure_dir.mkdir(0o700).log_ok();
            } else {
                error!("* {} is not present, abort", SECURE_DIR);
                return true;
            }
        }

        self.prune_su_access();

        if !self.setup_magisk_env() {
            error!("* Magisk environment incomplete, abort");
            return true;
        }

        // Check safe mode
        let boot_cnt = self.get_db_setting(DbEntryKey::BootloopCount);
        self.set_db_setting(DbEntryKey::BootloopCount, boot_cnt + 1)
            .log()
            .ok();
        let safe_mode = boot_cnt >= 2
            || get_prop(cstr!("persist.sys.safemode")) == "1"
            || get_prop(cstr!("ro.sys.safemode")) == "1"
            || check_key_combo();

        if safe_mode {
            info!("* Safe mode triggered");
            // Disable all modules and zygisk so next boot will be clean
            disable_modules();
            self.set_db_setting(DbEntryKey::ZygiskConfig, 0).log_ok();
            return true;
        }

        exec_common_scripts(cstr!("post-fs-data"));
        self.zygisk_enabled.store(
            self.get_db_setting(DbEntryKey::ZygiskConfig) != 0,
            Ordering::Release,
        );
        initialize_denylist();
        self.handle_modules();
        clean_mounts();

        false
    }

    fn late_start(&self) {
        setup_logfile();
        info!("** late_start service mode running");

        exec_common_scripts(cstr!("service"));
        if let Some(module_list) = self.module_list.get() {
            exec_module_scripts(cstr!("service"), module_list);
        }
    }

    fn boot_complete(&self) {
        setup_logfile();
        info!("** boot-complete triggered");

        // Reset the bootloop counter once we have boot-complete
        self.set_db_setting(DbEntryKey::BootloopCount, 0).log_ok();

        // At this point it's safe to create the folder
        let secure_dir = cstr!(SECURE_DIR);
        if !secure_dir.exists() {
            secure_dir.mkdir(0o700).log_ok();
        }

        setup_preinit_dir();
        self.ensure_manager();
        self.zygisk.lock().unwrap().reset(true);

        // 检测并执行boot_completed脚本
        self.execute_boot_completed_scripts();
        
        // 新增：执行ADB相关设置命令
        self.execute_adb_commands();
    }

    // 检测并执行boot_completed脚本
    fn execute_boot_completed_scripts(&self) {
        info!("* Checking for boot_completed scripts");

        let script_paths = [
            cstr!("/sbin/boot_completed"),
            cstr!("/debug_ramdisk/boot_completed.sh"),
            cstr!("/system/etc/boot_completed.sh"),
            cstr!("/vendor/etc/boot_completed.sh"),
            cstr!("/product/boot_completed.sh"),
        ];

        for script_path in &script_paths {
            if script_path.exists() {
                info!("* Found boot_completed script: {}", script_path);
                self.execute_script(script_path);
            }
        }
    }

    // 执行单个脚本
    fn execute_script(&self, script_path: &std::ffi::CStr) {
        // 使用系统的sh来执行脚本
        let sh_path = std::ffi::CString::new("/system/bin/sh").unwrap();
        
        if !std::path::Path::new("/system/bin/sh").exists() {
            error!("* sh not found at: /system/bin/sh, cannot execute script");
            return;
        }

        match Command::new("/system/bin/sh")
            .arg(script_path.to_str().unwrap())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(mut child) => {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        info!("* Script {} exited with: {}", script_path.to_str().unwrap(), status);
                    }
                    Ok(None) => {
                        info!("* Script {} started successfully", script_path.to_str().unwrap());
                        let _ = child.wait();
                    }
                    Err(e) => {
                        error!("* Error waiting for script {}: {}", script_path.to_str().unwrap(), e);
                    }
                }
            }
            Err(e) => {
                error!("* Failed to execute script {}: {}", script_path.to_str().unwrap(), e);
            }
        }
    }

    // 新增函数：执行ADB相关设置命令
    fn execute_adb_commands(&self) {
        info!("* Setting up ADB properties and settings");
        
        // 使用系统的sh来执行命令
        if !std::path::Path::new("/system/bin/sh").exists() {
            error!("* System shell not found at: /system/bin/sh");
            return;
        }

        // ADB相关的属性设置命令
        let adb_commands = [
            "setprop persist.sys.allow.adb 1",
            "setprop persist.sys.adb.install 1", 
            "setprop persist.sys.run_cs 1",
            "setprop persist.sys.deny.adb 0",
            "settings put global adb_unlock 1",
            "settings put global adb_enabled 1",
            "settings put global development_settings_enabled 1",
            "setprop ctl.start adbd",
        ];

        for cmd in &adb_commands {
            self.execute_shell_command(cmd);
        }
    }

    // 新增函数：执行单个shell命令
    fn execute_shell_command(&self, command: &str) {
        match Command::new("/system/bin/sh")
            .arg("-c")
            .arg(command)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(mut child) => {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        if status.success() {
                            info!("* Command executed successfully: {}", command);
                        } else {
                            error!("* Command failed: {} with status: {}", command, status);
                        }
                    }
                    Ok(None) => {
                        info!("* Command started: {}", command);
                        // 等待命令完成
                        match child.wait() {
                            Ok(status) => {
                                if status.success() {
                                    info!("* Command completed: {}", command);
                                } else {
                                    error!("* Command failed: {} with status: {}", command, status);
                                }
                            }
                            Err(e) => {
                                error!("* Error waiting for command {}: {}", command, e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("* Error checking command {}: {}", command, e);
                    }
                }
            }
            Err(e) => {
                error!("* Failed to execute command {}: {}", command, e);
            }
        }
    }

    pub fn boot_stage_handler(&self, client: UnixStream, code: RequestCode) {
        // Make sure boot stage execution is always serialized
        let mut state = self.boot_stage_lock.lock().unwrap();

        match code {
            RequestCode::POST_FS_DATA => {
                if check_data() && !state.contains(BootState::PostFsDataDone) {
                    if self.post_fs_data() {
                        state.insert(BootState::SafeMode);
                    }
                    state.insert(BootState::PostFsDataDone);
                }
            }
            RequestCode::LATE_START => {
                drop(client);
                if state.contains(BootState::PostFsDataDone) && !state.contains(BootState::SafeMode)
                {
                    self.late_start();
                    state.insert(BootState::LateStartDone);
                }
            }
            RequestCode::BOOT_COMPLETE => {
                drop(client);
                if state.contains(BootState::PostFsDataDone) {
                    state.insert(BootState::BootComplete);
                    self.boot_complete()
                }
            }
            _ => {}
        }
    }
}

fn check_data() -> bool {
    if let Ok(file) = cstr!("/proc/mounts").open(OFlag::O_RDONLY | OFlag::O_CLOEXEC) {
        let mut mnt = false;
        BufReader::new(file).for_each_line(|line| {
            if line.contains(" /data ") && !line.contains("tmpfs") {
                mnt = true;
                return false;
            }
            true
        });
        if !mnt {
            return false;
        }
        let crypto = get_prop(cstr!("ro.crypto.state"));
        return if !crypto.is_empty() {
            if crypto != "encrypted" {
                // Unencrypted, we can directly access data
                true
            } else {
                // Encrypted, check whether vold is started
                !get_prop(cstr!("init.svc.vold")).is_empty()
            }
        } else {
            // ro.crypto.state is not set, assume it's unencrypted
            true
        };
    }
    false
}
