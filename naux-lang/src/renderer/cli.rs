use crate::runtime::events::RuntimeEvent;

pub fn render_cli(events: &[RuntimeEvent]) {
    for ev in events {
        match ev {
            RuntimeEvent::Say(msg) => println!("{}", msg),
            RuntimeEvent::Ask { prompt, answer } => {
                println!("? ASK: {}", prompt);
                println!("= ORACLE: {}", answer);
            }
            RuntimeEvent::Fetch { target } => println!("~ fetch: {}", target),
            RuntimeEvent::Ui { kind, .. } => println!("~ ui: {}", kind),
            RuntimeEvent::Text(text) => println!("text: {}", text),
            RuntimeEvent::Button(label) => println!("[{}]", label),
            RuntimeEvent::Log(msg) => eprintln!("log: {}", msg),
        }
    }
}
