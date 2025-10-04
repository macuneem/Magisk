            // Abort upon any error occurred
            exit_on_error(true);

            // ack
            client.write_pod(&0).ok();

            exec_root_shell(
                client.into_raw_fd(),
                cred.pid.unwrap_or(-1),
                &mut req,
                info.cfg.mnt_ns,
            );
            return;
        }
        if child < 0 {
            error!("su: fork failed, abort");
            return;
        }

        // Wait result
        debug!("su: waiting child pid=[{}]", child);
        let mut status = 0;
        let code = unsafe {
            if libc::waitpid(child, &mut status, 0) > 0 {
                libc::WEXITSTATUS(status)
            } else {
                -1
            }
        };
        debug!("su: return code=[{}]", code);
        client.write_pod(&code).ok();
    }

    fn get_su_info(&self, uid: i32) -> Arc<SuInfo> {
        if uid == AID_ROOT {
            return Arc::new(SuInfo::allow(AID_ROOT));
        }

        let cached = self.cached_su_info.load();
        if cached.uid == uid && cached.access.lock().unwrap().is_fresh() {
            return cached;
        }

        let info = self.build_su_info(uid);
        self.cached_su_info.store(info.clone());
        info
    }

    #[cfg(feature = "su-check-db")]
    fn build_su_info(&self, uid: i32) -> Arc<SuInfo> {
        let result: LoggedResult<Arc<SuInfo>> = try {
            let cfg = self.get_db_settings()?;

            // Check multiuser settings
            let eval_uid = match cfg.multiuser_mode {
                MultiuserMode::OwnerOnly => {
                    if to_user_id(uid) != 0 {
                        return Arc::new(SuInfo::deny(uid));
                    }
                    uid
                }
                MultiuserMode::OwnerManaged => to_app_id(uid),
                _ => uid,
            };

            let mut access = RootSettings::default();
            self.get_root_settings(eval_uid, &mut access)?;

            // We need to talk to the manager, get the app info
            let (mgr_uid, mgr_pkg) =
                if access.policy == SuPolicy::Query || access.log || access.notify {
                    self.get_manager(to_user_id(eval_uid), true)
                } else {
                    (-1, String::new())
                };

            // If it's the manager, allow it silently
            if to_app_id(uid) == to_app_id(mgr_uid) {
                return Arc::new(SuInfo::allow(uid));
            }

            // Check su access settings
            match cfg.root_access {
                RootAccess::Disabled => {
                    warn!("Root access is disabled!");
                    return Arc::new(SuInfo::deny(uid));
                }
                RootAccess::AdbOnly => {
                    if uid != AID_SHELL {
                        warn!("Root access limited to ADB only!");
                        return Arc::new(SuInfo::deny(uid));
                    }
                }
                RootAccess::AppsOnly => {
                    if uid == AID_SHELL {
                        warn!("Root access is disabled for ADB!");
                        return Arc::new(SuInfo::deny(uid));
                    }
                }
                _ => {}
            };

            // If still not determined, check if manager exists
            if access.policy == SuPolicy::Query && mgr_uid < 0 {
                return Arc::new(SuInfo::deny(uid));
            }

            // Finally, the SuInfo
            Arc::new(SuInfo {
                uid,
                eval_uid,
                mgr_pkg,
                mgr_uid,
                cfg,
                access: Mutex::new(AccessInfo::new(access)),
            })
        };

        result.unwrap_or(Arc::new(SuInfo::deny(uid)))
    }

    #[cfg(not(feature = "su-check-db"))]
    fn build_su_info(&self, uid: i32) -> Arc<SuInfo> {
        Arc::new(SuInfo::allow(uid))
    }
}
