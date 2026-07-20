use crate::runtime::RuntimeEvent;

pub fn render_cli(events: &[RuntimeEvent]) {
    for ev in events {
        match ev {
            RuntimeEvent::AskRequest(prompt) => println!("[ask] {}", prompt),
            RuntimeEvent::AskResponse(answer) => println!("[answer] {}", answer),
            RuntimeEvent::Say(msg) => println!("{}", msg),
            RuntimeEvent::Fetch(target) => println!("[fetch] {}", target),
            RuntimeEvent::Text(text) => println!("{}", text),
            RuntimeEvent::Button(label) => println!("[button] {}", label),
            RuntimeEvent::Log(msg) => println!("[log] {}", msg),
            RuntimeEvent::Ui(kind) => println!("[ui] {}", kind),
        }
    }
}

pub fn render_html(events: &[RuntimeEvent]) -> String {
    let mut out = String::from("<html><body>");
    for ev in events {
        match ev {
            RuntimeEvent::AskRequest(prompt) => {
                out.push_str(&format!("<p class=\"ask\">{}</p>", escape_html(prompt)))
            }
            RuntimeEvent::AskResponse(answer) => {
                out.push_str(&format!("<p class=\"answer\">{}</p>", escape_html(answer)))
            }
            RuntimeEvent::Say(msg) => {
                out.push_str(&format!("<p class=\"say\">{}</p>", escape_html(msg)))
            }
            RuntimeEvent::Fetch(target) => {
                out.push_str(&format!("<p class=\"fetch\">{}</p>", escape_html(target)))
            }
            RuntimeEvent::Text(text) => {
                out.push_str(&format!("<p class=\"text\">{}</p>", escape_html(text)))
            }
            RuntimeEvent::Button(label) => {
                out.push_str(&format!("<button>{}</button>", escape_html(label)))
            }
            RuntimeEvent::Log(msg) => {
                out.push_str(&format!("<pre class=\"log\">{}</pre>", escape_html(msg)))
            }
            RuntimeEvent::Ui(kind) => {
                out.push_str(&format!("<div class=\"ui\">{}</div>", escape_html(kind)))
            }
        }
    }
    out.push_str("</body></html>");
    out
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
