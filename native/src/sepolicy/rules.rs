use crate::consts::{SEPOL_FILE_TYPE, SEPOL_LOG_TYPE, SEPOL_PROC_DOMAIN};
use crate::{SePolicy, ffi::Xperm};
use base::{LogLevel, set_log_level_state};

macro_rules! rules {
    (@args all) => {
        vec![]
    };
    (@args xall) => {
        vec![Xperm { low: 0x0000, high: 0xFFFF, reset: false }]
    };
    (@args svcmgr) => {
        vec!["servicemanager", "vndservicemanager", "hwservicemanager"]
    };
    (@args [proc]) => {
        vec![SEPOL_PROC_DOMAIN]
    };
    (@args [file]) => {
        vec![SEPOL_FILE_TYPE]
    };
    (@args [log]) => {
        vec![SEPOL_LOG_TYPE]
    };
    (@args proc) => {
        SEPOL_PROC_DOMAIN
    };
    (@args file) => {
        SEPOL_FILE_TYPE
    };
    (@args log) => {
        SEPOL_LOG_TYPE
    };
    (@args [$($arg:tt)*]) => {
        vec![$($arg)*]
    };
    (@args $arg:expr) => {
        $arg
    };
    (@stmt $self:ident) => {};
    (@stmt $self:ident $action:ident($($args:tt),*); $($res:tt)*) => {
        $self.$action($(rules!(@args $args)),*);
        rules!{@stmt $self $($res)* }
    };
    (use $self:ident; $($res:tt)*) => {{
        rules!{@stmt $self $($res)* }
    }};
}

impl SePolicy {
    pub fn magisk_rules(&mut self) {
        // Temp suppress warnings
        set_log_level_state(LogLevel::Warn, false);
        
        rules! {
            use self;
            
            // ==================== 基础类型定义 ====================
            type_(proc, ["domain"]);
            typeattribute([proc], ["mlstrustedsubject", "netdomain", "appdomain"]);
            type_(file, ["file_type"]);
            typeattribute([file], ["mlstrustedobject"]);
            type_(log, ["file_type"]);
            typeattribute([log], ["mlstrustedobject"]);
            
            // 定义系统应用相关类型
            type_("system_app_exec", ["file_type"]);
            type_("priv_app_exec", ["file_type"]);
            type_("platform_app_exec", ["file_type"]);
            
            // ==================== 宽容模式设置 ====================
            // 将所有重要域设置为宽容模式
            permissive(["shell", "platform_app", "untrusted_app_all", "untrusted_app", 
                       "priv_app", "system_app", "zygote", "system_server", "init", 
                       "vendor_init", "kernel", "adbd", "servicemanager", "hwservicemanager"]);
            permissive([proc]);  // Magisk 自身域
            
            // ==================== 防止策略被篡改 ====================
            deny(all, ["kernel"], ["security"], ["load_policy"]);
            deny(all, ["init", "vendor_init"], ["security"], ["setenforce"]);
            
            // ==================== 文件系统访问 ====================
            // 允许所有域访问基础文件类型
            allow(["domain"], [file],
                ["file", "dir", "fifo_file", "chr_file", "lnk_file", "sock_file", "blk_file"], all);
            
            // 特别允许系统应用访问各种文件系统
            allow(["system_app", "priv_app", "platform_app"], 
                  ["system_file", "apk_data_file", "app_data_file", "tmpfs", "rootfs"],
                  ["file", "dir"], all);
                  
            // 允许系统应用执行Magisk相关二进制文件
            allow(["system_app", "priv_app"], [proc], ["file"], ["execute", "execute_no_trans", "open", "read"]);
            allow(["system_app", "priv_app"], ["system_file", "magisk_file"], ["file"], ["execute", "open", "read"]);
            
            // ==================== 进程间通信 ====================
            // 允许系统应用与Magisk守护进程通信
            allow(["system_app", "priv_app", "platform_app"], [proc], 
                  ["unix_stream_socket", "unix_dgram_socket"], 
                  ["connectto", "getopt", "read", "write", "getattr", "setopt"]);
                  
            // 允许Magisk与系统应用通信
            allow([proc], ["system_app", "priv_app", "platform_app"], 
                  ["unix_stream_socket", "unix_dgram_socket"], 
                  ["accept", "listen", "read", "write", "getattr"]);
                  
            // Binder通信 - 允许系统应用与各种服务管理器交互
            allow(svcmgr, ["system_app", "priv_app", "platform_app"], 
                  ["dir"], ["search"]);
            allow(svcmgr, ["system_app", "priv_app", "platform_app"], 
                  ["file"], ["open", "read", "map"]);
            allow(svcmgr, ["system_app", "priv_app", "platform_app"], 
                  ["process"], ["getattr"]);
                  
            // 允许系统应用通过binder调用Magisk
            allow(["system_app", "priv_app", "platform_app"], [proc], 
                  ["binder"], ["call", "transfer"]);
            allow([proc], ["system_app", "priv_app", "platform_app"], 
                  ["binder"], ["call", "transfer"]);
                  
            // ==================== 进程控制 ====================
            // 允许系统应用执行su命令并切换到Magisk域
            allow(["system_app", "priv_app", "platform_app"], [proc], 
                  ["process"], ["fork", "sigchld", "sigkill", "ptrace", "getattr", "setpgid"]);
                  
            // 允许域转换
            allow(["system_app", "priv_app", "platform_app"], [proc], 
                  ["process"], ["dyntransition", "transition"]);
                  
            // ==================== 网络访问 ====================
            // 允许系统应用和Magisk进行网络通信
            allow(["system_app", "priv_app", "platform_app", proc], 
                  ["tcp_socket", "udp_socket", "rawip_socket", "netlink_socket"], 
                  all, all);
                  
            // ==================== 系统属性 ====================
            // 允许系统应用和Magisk读写系统属性
            allow(["system_app", "priv_app", "platform_app", proc], 
                  ["property_type", "system_prop"], 
                  ["file"], ["read", "write", "open", "getattr"]);
                  
            // ==================== 设备访问 ====================
            // 允许访问块设备、字符设备等
            allow(["system_app", "priv_app", "platform_app", proc], 
                  ["blk_device", "chr_device", "dev_type"], 
                  ["blk_file", "chr_file"], all);
                  
            // ==================== IOCTL权限 ====================
            // 允许所有必要的ioctl操作
            allowxperm(["system_app", "priv_app", "platform_app", proc], 
                      ["fs_type", "dev_type", "file_type", "blk_device", "chr_device"],
                      ["blk_file", "chr_file", "fifo_file"], xall);
                      
            allowxperm(["system_app", "priv_app", "platform_app", proc], 
                      ["tcp_socket", "udp_socket", "rawip_socket"], 
                      ["socket"], xall);
                      
            // ==================== 日志系统 ====================
            // 允许所有进程输出日志
            allow(["domain"], [log], ["fifo_file"], ["write"]);
            allow(["zygote"], [log], ["fifo_file"], ["open", "read"]);
            
            // 允许系统应用和Magisk访问系统日志
            allow(["system_app", "priv_app", "platform_app", proc], 
                  ["kernel", "system_data_file"], 
                  ["file", "dir"], ["read", "write", "open"]);
                  
            // ==================== Zygisk支持 ====================
            // Zygisk相关规则
            allow(["zygote"], ["zygote"], ["process"], ["execmem", "execstack"]);
            allow(["system_server"], ["system_server"], ["process"], ["execmem", "execstack"]);
            allow([proc], ["zygote", "system_server"], ["process"], ["ptrace", "getattr"]);
            
            // ==================== 挂载操作 ====================
            // 允许Magisk执行挂载操作
            allow([proc], ["fs_type", "dev_type", "file_type", "rootfs", "tmpfs"], 
                  ["filesystem"], ["mount", "unmount", "remount"]);
                  
            // 允许系统应用访问挂载点
            allow(["system_app", "priv_app", "platform_app"], 
                  ["mnt_media_rw", "mnt_runtime", "mnt_user"], 
                  ["dir", "file"], all);
                  
            // ==================== SELinux操作 ====================
            // 允许文件重标签
            allow(["kernel"], all, ["file"], ["relabelto"]);
            allow(["kernel"], ["tmpfs"], ["file"], ["relabelfrom"]);
            allow(["rootfs"], ["labeledfs", "tmpfs"], ["filesystem"], ["associate"]);
            
            // ==================== Init进程相关 ====================
            // 允许init进程管理Magisk
            allow(["init", "vendor_init"], [proc], ["process"], all);
            allow(["kernel"], [proc], ["process"], ["dyntransition"]);
            allow(["kernel"], ["kernel"], ["process"], ["setcurrent"]);
            
            // ==================== 特殊规则 ====================
            // 允许访问tmpfs文件
            allow(["init", "zygote", "shell", "platform_app", "system_app", "priv_app", 
                   "untrusted_app", "untrusted_app_all", proc], 
                  ["tmpfs"], ["file", "dir"], all);
                  
            // 允许magiskinit daemon记录日志
            allow(["kernel"], ["rootfs", "tmpfs"], ["chr_file"], ["write"]);
            
            // 允许magiskinit daemon处理mock selinuxfs
            allow(["kernel"], ["tmpfs"], ["fifo_file"], ["open", "read", "write"]);
            
            // ==================== 安全限制例外 ====================
            // 解除一些不必要的限制
            dontaudit(["init", "vendor_init"], ["adb_data_file"], ["dir"], ["search"]);
            
            // ==================== 系统应用特殊权限 ====================
            // 允许系统应用执行特权操作
            allow(["system_app", "priv_app"], ["system_data_file", "data_file"], 
                  ["dir", "file"], ["create", "write", "setattr", "unlink"]);
                  
            // 允许系统应用安装包
            allow(["system_app", "priv_app"], ["apk_data_file", "apk_tmp_file"], 
                  ["file", "dir"], all);
                  
            // ==================== Magisk守护进程权限 ====================
            // Magisk守护进程的完整权限
            allow([proc], [
                "fs_type", "dev_type", "file_type", "domain", "property_type",
                "service_manager_type", "hwservice_manager_type", "vndservice_manager_type",
                "port_type", "node_type", "system_prop", "kernel", "security"
            ], all, all);
            
            // ==================== 最终宽容保障 ====================
            // 确保所有可能涉及的域都是宽容的
            permissive(["bluetooth", "nfc", "radio", "drmserver", "mediaserver", 
                       "surfaceflinger", "bootanim", "netd", "wifi", "gpsd"]);
        }

        // 移除所有dontaudit规则以简化策略（可选）
        #[cfg(any())]
        self.strip_dontaudit();

        set_log_level_state(LogLevel::Warn, true);
    }
}
