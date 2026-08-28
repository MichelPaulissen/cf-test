use std::collections::BTreeSet;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, Thread32First, Thread32Next,
    PROCESSENTRY32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::Threading::{
    OpenThread, ResumeThread, SuspendThread, THREAD_SUSPEND_RESUME,
};

/// A reversible all-thread suspension for a bounded Windows task process tree.
/// Windows process-isolated containers expose their processes to the host.
/// containerd/runhcs does not implement its pause RPC for these containers, so
/// the node freezes the task entry process and descendants at the documented
/// Windows thread-control layer without touching the container service process.
pub struct SuspendedWindowsProcesses {
    thread_ids: BTreeSet<u32>,
    threads: Vec<HANDLE>,
    resumed: bool,
}

impl SuspendedWindowsProcesses {
    pub fn new() -> Self {
        Self {
            thread_ids: BTreeSet::new(),
            threads: Vec::new(),
            resumed: false,
        }
    }

    /// Suspends every not-yet-captured thread owned by `process_ids`. Call this
    /// until it returns zero; once a stable pass is reached, no suspended process
    /// can create a new thread or child process.
    pub fn suspend_processes(&mut self, process_ids: &[u32]) -> Result<usize, String> {
        if self.resumed {
            return Err("Windows process suspension was already resumed".to_owned());
        }
        if process_ids.is_empty() || process_ids.len() > 4_096 {
            return Err("Windows container process inventory is empty or oversized".to_owned());
        }
        let process_ids = process_ids.iter().copied().collect::<BTreeSet<_>>();
        if process_ids.contains(&0) {
            return Err("Windows container process inventory contains PID zero".to_owned());
        }

        // SAFETY: the snapshot handle is checked and closed by SnapshotHandle.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!(
                "snapshot Windows container threads: {}",
                std::io::Error::last_os_error()
            ));
        }
        let snapshot = SnapshotHandle(snapshot);
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        // SAFETY: `snapshot` is live and `entry` has the documented size.
        if unsafe { Thread32First(snapshot.0, &mut entry) } == 0 {
            return Err(format!(
                "enumerate Windows container threads: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut added = 0_usize;
        loop {
            if process_ids.contains(&entry.th32OwnerProcessID)
                && !self.thread_ids.contains(&entry.th32ThreadID)
            {
                // SAFETY: the numeric thread ID came from the live system snapshot;
                // inheritance is disabled and the returned handle is checked.
                let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                if thread.is_null() {
                    return Err(format!(
                        "open Windows container thread {} for suspension: {}",
                        entry.th32ThreadID,
                        std::io::Error::last_os_error()
                    ));
                }
                // SAFETY: `thread` is a live THREAD_SUSPEND_RESUME handle.
                if unsafe { SuspendThread(thread) } == u32::MAX {
                    // SAFETY: the failed suspension still returned an owned handle.
                    unsafe { CloseHandle(thread) };
                    return Err(format!(
                        "suspend Windows container thread {}: {}",
                        entry.th32ThreadID,
                        std::io::Error::last_os_error()
                    ));
                }
                self.thread_ids.insert(entry.th32ThreadID);
                self.threads.push(thread);
                added += 1;
            }
            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            // SAFETY: `snapshot` and `entry` remain live for the enumeration.
            if unsafe { Thread32Next(snapshot.0, &mut entry) } == 0 {
                break;
            }
        }
        if self.threads.is_empty() {
            return Err(
                "Windows container process inventory contained no suspendable threads".to_owned(),
            );
        }
        Ok(added)
    }

    /// Suspends the task entry process and all of its descendants. Container
    /// service processes are intentionally outside this tree: they are runtime
    /// infrastructure, not participants in the Clusterflux debug epoch.
    pub fn suspend_process_tree(&mut self, root_process_id: u32) -> Result<usize, String> {
        let process_ids = windows_process_tree(root_process_id)?;
        self.suspend_processes(&process_ids)
    }

    pub fn suspended_thread_count(&self) -> usize {
        self.threads.len()
    }

    pub fn resume(&mut self) -> Result<(), String> {
        self.resume_inner()
    }

    fn resume_inner(&mut self) -> Result<(), String> {
        if self.resumed {
            return Ok(());
        }
        let mut first_error = None;
        for thread in self.threads.drain(..).rev() {
            // SAFETY: every handle was suspended exactly once and remains owned.
            if unsafe { ResumeThread(thread) } == u32::MAX && first_error.is_none() {
                first_error = Some(format!(
                    "resume Windows container thread: {}",
                    std::io::Error::last_os_error()
                ));
            }
            // SAFETY: each owned handle is closed exactly once.
            unsafe { CloseHandle(thread) };
        }
        self.thread_ids.clear();
        self.resumed = true;
        first_error.map_or(Ok(()), Err)
    }
}

fn windows_process_tree(root_process_id: u32) -> Result<Vec<u32>, String> {
    if root_process_id == 0 {
        return Err("Windows task entry process is PID zero".to_owned());
    }
    // SAFETY: the snapshot handle is checked and closed by SnapshotHandle.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(format!(
            "snapshot Windows task processes: {}",
            std::io::Error::last_os_error()
        ));
    }
    let snapshot = SnapshotHandle(snapshot);
    let mut entry = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };
    // SAFETY: `snapshot` is live and `entry` has the documented size.
    if unsafe { Process32First(snapshot.0, &mut entry) } == 0 {
        return Err(format!(
            "enumerate Windows task processes: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut parent_by_process = Vec::new();
    loop {
        parent_by_process.push((entry.th32ProcessID, entry.th32ParentProcessID));
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
        // SAFETY: `snapshot` and `entry` remain live for the enumeration.
        if unsafe { Process32Next(snapshot.0, &mut entry) } == 0 {
            break;
        }
    }
    if !parent_by_process
        .iter()
        .any(|(process, _)| *process == root_process_id)
    {
        return Err(format!(
            "Windows task entry process {root_process_id} is no longer running"
        ));
    }
    let mut tree = BTreeSet::from([root_process_id]);
    loop {
        let before = tree.len();
        for (process, parent) in &parent_by_process {
            if tree.contains(parent) {
                tree.insert(*process);
            }
        }
        if tree.len() == before {
            break;
        }
        if tree.len() > 4_096 {
            return Err("Windows task process tree is oversized".to_owned());
        }
    }
    Ok(tree.into_iter().collect())
}

impl Default for SuspendedWindowsProcesses {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SuspendedWindowsProcesses {
    fn drop(&mut self) {
        let _ = self.resume_inner();
    }
}

struct SnapshotHandle(HANDLE);

impl Drop for SnapshotHandle {
    fn drop(&mut self) {
        // SAFETY: this handle was returned by CreateToolhelp32Snapshot and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}
