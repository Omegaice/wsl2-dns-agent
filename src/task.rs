use std::mem::ManuallyDrop;
use win32_utils::error::check_error;
use windows::{
    core::{Interface, Result, PSTR},
    Win32::{
        Foundation::BSTR,
        Security::Authentication::Identity::{
            GetUserNameExA, NameSamCompatible, EXTENDED_NAME_FORMAT,
        },
        System::{
            Com::{
                CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_MULTITHREADED, VARIANT,
                VARIANT_0, VARIANT_0_0, VARIANT_0_0_0,
            },
            Ole::VT_I4,
            TaskScheduler::{
                IEventTrigger, IExecAction, ITaskService, TaskScheduler, TASK_ACTION_EXEC,
                TASK_CREATE_OR_UPDATE, TASK_LOGON_INTERACTIVE_TOKEN, TASK_TRIGGER_EVENT, TASK_RUNLEVEL_HIGHEST, TASK_RUNLEVEL_TYPE,
            },
        },
    },
};

pub fn create_interface_priority_task() -> Result<()> {
    unsafe {
        // Initialize the COM runtime for this thread
        CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED)?;

        let service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_ALL)?;

        service.Connect(
            VARIANT::default(),
            VARIANT::default(),
            VARIANT::default(),
            VARIANT::default(),
        )?;

        if task_already_exists(&service)? {
            log::info!("Task already exists");
            return Ok(());
        }

        create_task(&service)
    }
}

unsafe fn task_already_exists(service: &ITaskService) -> Result<bool> {
    let root_folder = service.GetFolder(BSTR::from("\\"))?;

    let task_list = root_folder.GetTasks(0)?;
    for i in 0..task_list.Count()? {
        // Create u16 variant for index
        let mut task_variant = VARIANT {
            Anonymous: VARIANT_0 {
                Anonymous: ManuallyDrop::new(VARIANT_0_0 {
                    vt: VT_I4.0 as u16,
                    wReserved1: 0,
                    wReserved2: 0,
                    wReserved3: 0,
                    Anonymous: VARIANT_0_0_0 { lVal: i + 1 },
                }),
            },
        };

        let task = task_list.get_Item(&task_variant)?;

        // Cleanup Variant
        drop(&mut task_variant.Anonymous.Anonymous);

        let name = task.Name()?.to_string();
        if name.eq_ignore_ascii_case("Update AnyConnect Adapter Interface Metric for WSL2") {
            return Ok(true);
        }

        // Verify Run Level
        let principal = task.Definition()?.Principal()?;

        let mut run_level = TASK_RUNLEVEL_TYPE(10);
        principal.RunLevel(&mut run_level)?;

        if run_level != TASK_RUNLEVEL_HIGHEST {
            log::info!(r#"Task requires updating to use administrator permissions. 
            - Open task scheduler:
            - Double click "Update AnyConnect Adapter Interface Metric for WSL2"
            - Security options: Check "Run with highest privileges""#);
        }
    }

    Ok(false)
}

unsafe fn create_task(service: &ITaskService) -> Result<()> {
    let task_definition = service.NewTask(0)?;

    let reg_info = task_definition.RegistrationInfo()?;
    reg_info.SetDescription(BSTR::from(
        "Change interface priority for Cisco AnyConnect to 6000 upon connection and disconnection.",
    ))?;

    let user = get_current_username(NameSamCompatible)?;
    reg_info.SetAuthor(BSTR::from(&user))?;

    let principal = task_definition.Principal()?;
    principal.SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN)?;
    // principal.SetRunLevel(TASK_RUNLEVEL_HIGHEST)?;

    let settings = task_definition.Settings()?;
    settings.SetEnabled(1)?;
    settings.SetStartWhenAvailable(0)?;
    settings.SetHidden(0)?;
    settings.SetDisallowStartIfOnBatteries(0)?;
    settings.SetStopIfGoingOnBatteries(0)?;

    let idle_settings = settings.IdleSettings()?;
    idle_settings.SetStopOnIdleEnd(1)?;
    idle_settings.SetRestartOnIdle(0)?;

    let triggers = task_definition.Triggers()?;
    let trigger: IEventTrigger = triggers.Create(TASK_TRIGGER_EVENT)?.cast()?;
    trigger.SetEnabled(1)?;
    trigger.SetSubscription(BSTR::from(
        r#"<QueryList>
            <Query Id="0" Path="Cisco AnyConnect Secure Mobility Client">
                <Select Path="Cisco AnyConnect Secure Mobility Client">*[System[Provider[@Name='acvpnagent'] and (EventID=2039 or EventID=2041)]]</Select>
            </Query>
        </QueryList>"#
    ))?;

    let action: IExecAction = task_definition
        .Actions()?
        .Create(TASK_ACTION_EXEC)?
        .cast()?;
    action.SetPath(BSTR::from(
        r#"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"#,
    ))?;
    action.SetArguments(BSTR::from(r#"-Command "& {Get-NetAdapter | Where-Object {$_.InterfaceDescription -Match 'Cisco AnyConnect'} | Set-NetIPInterface -InterfaceMetric 6000}""#))?;

    service
        .GetFolder(BSTR::from("\\"))?
        .RegisterTaskDefinition(
            &BSTR::from("Update AnyConnect Adapter Interface Metric for WSL2"),
            task_definition,
            TASK_CREATE_OR_UPDATE.0,
            VARIANT::default(),
            VARIANT::default(),
            TASK_LOGON_INTERACTIVE_TOKEN,
            VARIANT::default(),
        )?;

    log::info!("task created");

    Ok(())
}

unsafe fn get_current_username(fmt: EXTENDED_NAME_FORMAT) -> Result<String> {
    let mut name_buffer_size = 257_u32;
    let mut name_buffer = Vec::<u8>::with_capacity(name_buffer_size as usize);
    let name = PSTR(name_buffer.as_mut_ptr());

    check_error(|| GetUserNameExA(fmt, name, &mut name_buffer_size))?;
    let buffer = std::slice::from_raw_parts(name.0, name_buffer_size as usize);

    return Ok(String::from_utf8_lossy(buffer).to_string());
}
