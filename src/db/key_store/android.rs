//! Process-lifetime Android context registration and startup serialization.
use crate::error::{Error, Result};

#[derive(Default)]
struct ContextState {
    registered: bool,
    opening: usize,
    opened: bool,
}

impl ContextState {
    /// Returns true only for first registration.
    fn register(&mut self, same: bool) -> Result<bool> {
        if self.opened {
            return Err(Error::Config(
                "Android context cannot initialize after a successful core open".into(),
            ));
        }
        if self.registered {
            return if same {
                Ok(false)
            } else {
                Err(Error::Config(
                    "conflicting Android application context".into(),
                ))
            };
        }
        if self.opening != 0 || self.opened {
            return Err(Error::Config(
                "Android context cannot change after core startup begins".into(),
            ));
        }
        self.registered = true;
        Ok(true)
    }
    fn begin(&mut self) -> Result<()> {
        if !self.registered {
            return Err(Error::Config(
                "call fh_android_init before opening the core".into(),
            ));
        }
        self.opening += 1;
        Ok(())
    }
    fn finish(&mut self, success: bool) {
        self.opening -= 1;
        self.opened |= success;
    }
}

#[cfg(target_os = "android")]
mod platform {
    use super::*;
    use jni::{JavaVM, objects::JObject};
    use std::ffi::c_void;
    use std::sync::Mutex;

    struct Registration {
        state: ContextState,
        // Borrowed process-lifetime host pointers, accessed under CONTEXT.
        pointers: Option<(usize, usize)>,
    }
    static CONTEXT: Mutex<Registration> = Mutex::new(Registration {
        state: ContextState {
            registered: false,
            opening: 0,
            opened: false,
        },
        pointers: None,
    });

    fn context_error() -> Error {
        Error::Config("Android context initialization failed".into())
    }

    fn register_context(
        java_vm: *mut c_void,
        application_context_global_ref: *mut c_void,
        initialize_ndk_context: bool,
    ) -> Result<()> {
        if java_vm.is_null() || application_context_global_ref.is_null() {
            return Err(context_error());
        }
        let mut context = CONTEXT.lock().map_err(|_| context_error())?;
        // SAFETY: the caller guarantees that java_vm is the process JavaVM.
        let vm = unsafe { JavaVM::from_raw(java_vm.cast()) }.map_err(|_| context_error())?;
        let env = vm.attach_current_thread().map_err(|_| context_error())?;
        let same = if let Some((old_vm, old_ref)) = context.pointers {
            if old_vm != java_vm as usize {
                return Err(context_error());
            }
            // SAFETY: these are borrowed global references; JObject does not
            // delete them, and the host keeps them valid for the process.
            let old = unsafe { JObject::from_raw(old_ref as jni::sys::jobject) };
            let new = unsafe { JObject::from_raw(application_context_global_ref.cast()) };
            env.is_same_object(&old, &new)
                .map_err(|_| context_error())?
        } else {
            false
        };
        let initialize = context.state.register(same)?;
        if initialize {
            if initialize_ndk_context {
                // SAFETY: the startup mutex serializes first registration, and
                // the host excludes independent ndk-context initialization/users.
                // Registered contexts are never released or replaced.
                unsafe {
                    ndk_context::initialize_android_context(
                        java_vm,
                        application_context_global_ref,
                    );
                }
            }
            context.pointers = Some((java_vm as usize, application_context_global_ref as usize));
        }
        Ok(())
    }

    /// # Safety
    /// Both pointers must be valid for the process lifetime. The context must
    /// be a JNI global reference to Application.getApplicationContext(). The
    /// host must not initialize/release ndk-context independently.
    pub(crate) unsafe fn initialize_android_context(
        java_vm: *mut c_void,
        application_context_global_ref: *mut c_void,
    ) -> Result<()> {
        // SAFETY: validity and lifetime of VM/global reference are host contracts.
        unsafe { register_context(java_vm, application_context_global_ref, true) }
    }

    /// Registers the Android context already installed by android-activity.
    /// Its startup hook stores an Application global reference in ndk-context;
    /// this path records the same borrowed pointers in core without attempting
    /// to initialize ndk-context a second time.
    pub(crate) fn initialize_existing_ndk_context() -> Result<()> {
        // SAFETY: callers must invoke this only after android-activity has
        // initialized ndk-context with its process-lifetime Application ref.
        let context = ndk_context::android_context();
        register_context(context.vm(), context.context(), false)
    }

    pub(crate) struct AndroidOpenGuard {
        finished: bool,
    }

    pub(crate) fn begin_core_open() -> Result<AndroidOpenGuard> {
        CONTEXT.lock().map_err(|_| context_error())?.state.begin()?;
        Ok(AndroidOpenGuard { finished: false })
    }

    impl AndroidOpenGuard {
        pub(crate) fn commit(mut self) {
            CONTEXT
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .state
                .finish(true);
            self.finished = true;
        }
    }
    impl Drop for AndroidOpenGuard {
        fn drop(&mut self) {
            if !self.finished {
                CONTEXT
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .state
                    .finish(false);
            }
        }
    }
}

#[cfg(target_os = "android")]
pub(crate) use platform::{
    begin_core_open, initialize_android_context, initialize_existing_ndk_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn context_requires_registration_and_failed_open_allows_retry() {
        let mut state = ContextState::default();
        assert!(state.begin().is_err());
        assert!(state.register(false).unwrap());
        assert!(!state.register(true).unwrap());
        state.begin().unwrap();
        assert!(state.register(false).is_err());
        state.finish(false);
        assert!(state.register(false).is_err());
        assert!(!state.register(true).unwrap());
    }
    #[test]
    fn conflicting_context_is_rejected_before_open() {
        let mut state = ContextState::default();
        state.register(false).unwrap();
        assert!(state.register(false).is_err());
        assert!(!state.register(true).unwrap());
    }
    #[test]
    fn successful_open_rejects_all_context_initialization() {
        let mut state = ContextState::default();
        state.register(false).unwrap();
        state.begin().unwrap();
        state.finish(true);
        assert!(state.register(false).is_err());
        assert!(state.register(true).is_err());
    }
}
