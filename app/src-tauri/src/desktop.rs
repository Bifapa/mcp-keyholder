//! Native confirmation window on its own Windows desktop.
//!
//! The desktop is switched away before the window appears: nothing of the user's session
//! is on screen or reachable by screen capture, synthetic input aimed at the normal
//! desktop, or HTML overlays drawn by an agent. The window is pure Win32 — no WebView —
//! and the typed password, PIN or code leaves this module only towards the core.
//!
//! The previous desktop is restored on every path: cancellation, errors and panics alike
//! (the guard restores it in `Drop`).

/// What the human has to type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Pin,
    Otp,
    Password,
    PasswordOtp,
}

/// Everything the window shows. `facts` come from the core (verified), `agent_note`
/// comes from the agent and is shown with an "as the agent claims" mark.
pub struct Prompt {
    pub heading: String,
    pub facts: Vec<(String, String)>,
    pub agent_note: Option<String>,
    pub antiphish: String,
    pub field: Field,
    /// Draw the anti-phishing word as moving noise (the "noise word" setting).
    pub noise: bool,
}

pub struct Answer {
    pub first: String,
    pub second: String,
}

#[cfg(windows)]
pub use win::{available, prompt, GIVE_UP_OVERRIDE_MS, TEST_HANG, TEST_NO_SWITCH};

#[cfg(not(windows))]
mod other {
    use super::{Answer, Prompt};

    pub static GIVE_UP_OVERRIDE_MS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    pub static TEST_NO_SWITCH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    pub static TEST_HANG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    pub fn available() -> bool {
        false
    }

    pub fn prompt(_p: Prompt) -> Result<Answer, String> {
        Err("the separate desktop is only available on Windows".into())
    }
}

#[cfg(not(windows))]
pub use other::{available, prompt, GIVE_UP_OVERRIDE_MS, TEST_HANG, TEST_NO_SWITCH};

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::ptr::null_mut;
    use std::sync::{LazyLock, Mutex};

    use windows_sys::Win32::Foundation::{GetLastError, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
    use windows_sys::Win32::Graphics::Gdi::{
        BeginPaint, CreateCompatibleDC, CreateDIBSection, CreateFontW, CreateSolidBrush, DeleteDC, DeleteObject, DrawTextW,
        EndPaint, ExcludeClipRect, FillRect, FrameRect, GdiFlush, InvalidateRect, SetTextCharacterExtra, StretchDIBits, BITMAPINFO, BITMAPINFOHEADER, BI_RGB,
        DIB_RGB_COLORS, SRCCOPY,
        SelectObject, SetBkColor, SetBkMode, SetTextColor, UpdateWindow, HBRUSH, HFONT, PAINTSTRUCT, TRANSPARENT,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::StationsAndDesktops::{
        CloseDesktop, CreateDesktopW, OpenDesktopW, OpenInputDesktop, SetThreadDesktop, SwitchDesktop, HDESK,
    };
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetFocus, SetFocus, VK_ESCAPE};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AdjustWindowRectEx, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect, GetMessageW,
        GetSystemMetrics, GetWindowTextLengthW, GetWindowTextW, IsDialogMessageW, KillTimer, LoadCursorW,
        PostMessageW, PostQuitMessage, RegisterClassW, SendMessageW, SetTimer, SetWindowDisplayAffinity, ShowWindow, SystemParametersInfoW,
        TranslateMessage, SPI_GETCLIENTAREAANIMATION, WDA_EXCLUDEFROMCAPTURE,
        IDC_ARROW, MSG, SM_CXSCREEN, SM_CYSCREEN, SW_SHOW, WM_CLOSE, WM_COMMAND, WM_CREATE, WM_CTLCOLOREDIT,
        WM_DESTROY, WM_ERASEBKGND,
        WM_KEYDOWN, WM_LBUTTONDOWN, WM_PAINT, WM_SETFONT, WM_TIMER, WNDCLASSW, WS_CAPTION, WS_CHILD, WS_CLIPCHILDREN,
        WS_EX_APPWINDOW,
        WS_EX_TOPMOST, WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
    };

    use super::{Answer, Field, Prompt};

    const ID_EDIT1: i32 = 100;
    const ID_EDIT2: i32 = 101;

    /// Timer 1 arms the buttons after a second; timer 2 cancels an unattended prompt; timer 3 is
    /// the heartbeat the watchdog in `prompt` checks.
    const TIMER_ARM: usize = 1;
    const TIMER_GIVE_UP: usize = 2;
    const TIMER_BEAT: usize = 3;
    /// Timer 4 moves the noise of the anti-phishing word.
    const TIMER_NOISE: usize = 4;
    const GIVE_UP_MS: u32 = 120_000;
    const BEAT_MS: u32 = 500;
    /// No heartbeat for this long means the window thread hangs: the screen is switched back.
    const HANG_MS: u64 = 4_000;

    static EPOCH: LazyLock<std::time::Instant> = LazyLock::new(std::time::Instant::now);
    static LAST_BEAT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn beat() {
        LAST_BEAT.store(EPOCH.elapsed().as_millis() as u64, std::sync::atomic::Ordering::SeqCst);
    }

    fn since_beat() -> u64 {
        (EPOCH.elapsed().as_millis() as u64).saturating_sub(LAST_BEAT.load(std::sync::atomic::Ordering::SeqCst))
    }

    /// Test mode (`--test-secure-desktop`) shortens the give-up timer; 0 = default.
    pub static GIVE_UP_OVERRIDE_MS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    /// Test mode with `--no-switch`: the same window on the current desktop.
    pub static TEST_NO_SWITCH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    /// Debug test mode with `--hang`: the window thread stops responding after a second, to
    /// check that the watchdog switches the screen back.
    pub static TEST_HANG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    fn give_up_ms() -> u32 {
        match GIVE_UP_OVERRIDE_MS.load(std::sync::atomic::Ordering::Relaxed) {
            0 => GIVE_UP_MS,
            v => v,
        }
    }

    /// The window has this long to appear; otherwise the screen is switched back regardless.
    const APPEAR_MS: u128 = 6_000;

    /// Switches the screen back to the normal desktop from any thread. Used when the prompt
    /// thread is stuck: the human must never be left on an empty desktop.
    unsafe fn emergency_restore() {
        let name = wide("Default");
        let h = OpenDesktopW(name.as_ptr(), 0, 0, 0x0100); // DESKTOP_SWITCHDESKTOP
        if !h.is_null() {
            SwitchDesktop(h);
            CloseDesktop(h);
        }
    }

    /// The window of the prompt in progress, so a stuck caller can close it.
    static CURRENT_HWND: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    /// Set once the window exists: after it closes, CURRENT_HWND is 0 again but that is not
    /// "never appeared".
    static APPEARED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    // Colors as COLORREF (0x00BBGGRR), matching the shared design tokens.
    const BG: u32 = 0x1A1012; // #12101A
    const TEXT: u32 = 0xF6EAED; // #EDEAF6
    const MUTED: u32 = 0xC09DA4; // #A49DC0
    const ACCENT: u32 = 0xE04A6D; // #6D4AE0
    const BORDER: u32 = 0x40272C; // #2C2740
    const FRAME: u32 = 0x5C4F4A; // #4A4F5C
    const WARN: u32 = 0x4AA1E0; // #E0A14A
    const ON_ACCENT: u32 = 0xFFFFFF;

    const W: i32 = 620;
    const PAD: i32 = 32;

    // DrawTextW flags.
    const DT_LEFT: u32 = 0x0000;
    const DT_CENTER: u32 = 0x0001;
    const DT_RIGHT: u32 = 0x0002;
    const DT_VCENTER: u32 = 0x0004;
    const DT_SINGLELINE: u32 = 0x0020;
    const DT_WORDBREAK: u32 = 0x0010;
    const DT_END_ELLIPSIS: u32 = 0x8000;

    /// Only one prompt at a time: it switches the whole desktop.
    static PROMPT_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    static UI: LazyLock<Mutex<Option<Ui>>> = LazyLock::new(|| Mutex::new(None));

    struct Ui {
        heading: String,
        facts: Vec<(String, String)>,
        note: Option<String>,
        antiphish: String,
        field: Field,
        hwnd: usize,
        edit1: usize,
        edit2: usize,
        fonts: Vec<HFONT>,
        bg: HBRUSH,
        field_bg: HBRUSH,
        accent: HBRUSH,
        frame: HBRUSH,
        layout: Layout,
        answer: Option<Answer>,
        /// Buttons stay dead for the first second, so a mis-click cannot approve.
        armed: bool,
        focus: usize,
        /// The first field shows its characters ("Show" next to its label).
        shown: bool,
        /// The anti-phishing word as moving noise; None draws it as plain text.
        noise: Option<Noise>,
    }

    // Raw window handles are only touched on the window's own thread.
    unsafe impl Send for Ui {}

    #[derive(Clone, Copy, Default)]
    struct Layout {
        heading_y: i32,
        divider_y: i32,
        facts_y: i32,
        note_y: i32,
        note_h: i32,
        phish_y: i32,
        input1_y: i32,
        input2_y: i32,
        height: i32,
    }

    fn labels(f: Field) -> (&'static str, Option<&'static str>) {
        match f {
            Field::Pin => ("PIN", None),
            Field::Otp => ("Authenticator code", None),
            Field::Password => ("Master password", None),
            Field::PasswordOtp => ("Master password", Some("Authenticator code")),
        }
    }

    fn mask_password(f: Field) -> bool {
        !matches!(f, Field::Otp)
    }

    /// The "Show / Hide" toggle on the label line of the first (masked) field.
    fn peek_rect(l: Layout) -> RECT {
        RECT { left: W - PAD - 140, top: l.input1_y - 2, right: W - PAD, bottom: l.input1_y + 20 }
    }

/// The box around an input whose label sits at `y`. The window draws the frame itself and the
    /// borderless edit control sits inside it: an edit's own border is non-client paint that the
    /// window could cover and never get back (the missing top line).
    fn field_rect(y: i32) -> RECT {
        RECT { left: PAD, top: y + 22, right: W - PAD, bottom: y + 54 }
    }

    // ---------- anti-phishing word as moving noise ----------
    //
    // Two noise fields drift in opposite directions: the background to the left, the inside of the
    // letters to the right. Every single frame is uniform noise, so a still capture shows no word;
    // in motion the opposing drift makes the letters stand out clearly. (The window is also
    // excluded from capture; this covers captures that get past that.)

    // Fine grain, big capitals and a steady drift keep the word readable in motion.
    const CELL: i32 = 2;
    const NOISE_MS: u32 = 40;
    // Each cell takes one of these greys at random.
    const GREYS: &[u32] = &[30, 105, 180, 255];

    struct Noise {
        w: usize,
        h: usize,
        mask: Vec<bool>,
        /// Random grey levels in [0, 1).
        back: Vec<f32>,
        letters: Vec<f32>,
        t: usize,
    }

    /// Where the word goes inside the anti-phishing box.
    fn word_rect(l: Layout) -> RECT {
        RECT { left: PAD + 12, top: l.phish_y + 28, right: W - PAD - 12, bottom: l.phish_y + 140 }
    }

    impl Noise {
        /// None when Windows animations are off: moving noise would then be unreadable, so the
        /// word is drawn as plain text.
        unsafe fn new(word: &str, area: RECT) -> Option<Noise> {
            let mut animate: i32 = 1;
            SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, &mut animate as *mut i32 as *mut c_void, 0);
            if animate == 0 {
                return None;
            }
            let w = ((area.right - area.left) / CELL) as usize;
            let h = ((area.bottom - area.top) / CELL) as usize;
            let mask = text_mask(word, w, h)?;
            // Visual noise, not a secret: xorshift seeded from the clock is enough.
            let mut seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x9E37_79B9_7F4A_7C15)
                | 1;
            let mut next = || {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                (seed >> 40) as f32 / (1u64 << 24) as f32
            };
            let back = (0..w * h).map(|_| next()).collect();
            let letters = (0..w * h).map(|_| next()).collect();
            Some(Noise { w, h, mask, back, letters, t: 0 })
        }

        fn frame(&self) -> Vec<u32> {
            let (w, h) = (self.w, self.h);
            // 1.5 cells per frame: fast enough to pick the letters out at a glance.
            let shift = (self.t * 3 / 2) % w;
            let mut px = vec![0u32; w * h];
            for y in 0..h {
                for x in 0..w {
                    let i = y * w + x;
                    let v = if self.mask[i] {
                        self.letters[y * w + (x + w - shift) % w] // drifts right
                    } else {
                        self.back[y * w + (x + shift) % w] // drifts left
                    };
                    // DIB pixels are 0x00RRGGBB; a grey has equal channels.
                    let g = GREYS[((v * GREYS.len() as f32) as usize).min(GREYS.len() - 1)];
                    px[i] = (g << 16) | (g << 8) | g;
                }
            }
            px
        }
    }

    fn dib_info(w: usize, h: usize) -> BITMAPINFO {
        let mut bmi: BITMAPINFO = unsafe { std::mem::zeroed() };
        bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bmi.bmiHeader.biWidth = w as i32;
        bmi.bmiHeader.biHeight = -(h as i32); // top-down rows
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;
        bmi
    }

    /// The word in capitals at cell resolution, as large as fits, centred, strokes one cell
    /// thicker on every side: true where a letter covers the cell.
    unsafe fn text_mask(word: &str, w: usize, h: usize) -> Option<Vec<bool>> {
        const DT_NOPREFIX: u32 = 0x0800;
        // Drawn into a taller scratch bitmap, then the inked box is measured and centred.
        let (sw, sh) = (w, h * 2);
        let dc = CreateCompatibleDC(null_mut());
        if dc.is_null() {
            return None;
        }
        let bmi = dib_info(sw, sh);
        let mut bits: *mut c_void = null_mut();
        let bmp = CreateDIBSection(dc, &bmi, DIB_RGB_COLORS, &mut bits, null_mut(), 0);
        if bmp.is_null() || bits.is_null() {
            DeleteDC(dc);
            return None;
        }
        let old_bmp = SelectObject(dc, bmp as _);
        SetBkMode(dc, TRANSPARENT as i32);
        SetTextColor(dc, 0x00FF_FFFF);
        SetTextCharacterExtra(dc, 2);
        let face = wide("Segoe UI");
        let mut text: Vec<u16> = word.to_uppercase().encode_utf16().collect();
        let px = std::slice::from_raw_parts_mut(bits as *mut u32, sw * sh);
        // Capitals are about 0.7 em, so this starts near the full height and shrinks to fit.
        let mut size = (h as i32 * 13) / 10;
        let mut ink = None;
        for _ in 0..12 {
            px.fill(0);
            // Non-antialiased: every cell is either letter or background.
            let font = CreateFontW(-size, 0, 0, 0, 900, 0, 0, 0, 1, 0, 0, 3, 0, face.as_ptr());
            let old_font = SelectObject(dc, font as _);
            let mut r = RECT { left: 2, top: 0, right: sw as i32, bottom: sh as i32 };
            DrawTextW(dc, text.as_mut_ptr(), text.len() as i32, &mut r, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
            GdiFlush();
            SelectObject(dc, old_font);
            DeleteObject(font as _);
            let (mut x0, mut y0, mut x1, mut y1) = (usize::MAX, usize::MAX, 0, 0);
            for y in 0..sh {
                for x in 0..sw {
                    if px[y * sw + x] & 0xFF > 0x80 {
                        x0 = x0.min(x);
                        y0 = y0.min(y);
                        x1 = x1.max(x);
                        y1 = y1.max(y);
                    }
                }
            }
            if x0 == usize::MAX {
                break; // nothing to draw
            }
            let (bw, bh) = (x1 - x0 + 1, y1 - y0 + 1);
            // Room for the thickening and a small margin; a word reaching the right edge was cut.
            if bw + 4 <= w && bh + 4 <= h && x1 + 1 < sw {
                ink = Some((x0, y0, bw, bh));
                break;
            }
            let by_w = size * (w as i32 - 6) / (bw as i32).max(1);
            let by_h = size * (h as i32 - 6) / (bh as i32).max(1);
            size = by_w.min(by_h).min(size * 9 / 10).max(6);
        }
        let thin = ink.map(|(x0, y0, bw, bh)| {
            let (ox, oy) = ((w - bw) / 2, (h - bh) / 2);
            let mut m = vec![false; w * h];
            for y in 0..bh {
                for x in 0..bw {
                    m[(oy + y) * w + ox + x] = px[(y0 + y) * sw + x0 + x] & 0xFF > 0x80;
                }
            }
            m
        });
        SelectObject(dc, old_bmp);
        DeleteObject(bmp as _);
        DeleteDC(dc);
        let thin = thin?;
        // One cell thicker on every side: thin strokes get lost in the noise.
        let at = |x: isize, y: isize| x >= 0 && y >= 0 && (x as usize) < w && (y as usize) < h && thin[y as usize * w + x as usize];
        let mut mask = vec![false; w * h];
        for y in 0..h as isize {
            for x in 0..w as isize {
                mask[y as usize * w + x as usize] = at(x, y) || at(x - 1, y) || at(x + 1, y) || at(x, y - 1) || at(x, y + 1);
            }
        }
        Some(mask)
    }

    unsafe fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn available() -> bool {
        unsafe {
            let h = OpenInputDesktop(0, 0, 0x0100);
            if h.is_null() {
                return false;
            }
            CloseDesktop(h);
            true
        }
    }

    pub fn prompt(p: Prompt) -> Result<Answer, String> {
        let _guard = PROMPT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        APPEARED.store(false, std::sync::atomic::Ordering::SeqCst);
        let (tx, rx) = std::sync::mpsc::channel::<Result<Answer, String>>();
        std::thread::Builder::new()
            .name("kh-secure-desktop".into())
            .spawn(move || {
                let r = run(p);
                let _ = tx.send(r);
            })
            .map_err(|e| format!("could not open the confirmation window: {e}"))?;
        // Watchdog. The window cancels itself after the give-up timer; on top of that, if it has
        // not appeared within APPEAR_MS, stops beating for HANG_MS, or outlives the timer, the
        // screen is switched back from here. The human is never left on an empty desktop.
        beat();
        let started = std::time::Instant::now();
        let limit = give_up_ms() as u128 + 10_000;
        loop {
            match rx.recv_timeout(std::time::Duration::from_millis(200)) {
                Ok(r) => return r,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    unsafe { emergency_restore() };
                    return Err("the confirmation window closed with an error".into());
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    let h = CURRENT_HWND.load(std::sync::atomic::Ordering::SeqCst);
                    let elapsed = started.elapsed().as_millis();
                    let appeared = APPEARED.load(std::sync::atomic::Ordering::SeqCst);
                    let hung = h != 0 && since_beat() > HANG_MS;
                    if (!appeared && elapsed > APPEAR_MS) || hung || elapsed > limit {
                        unsafe {
                            if h != 0 {
                                PostMessageW(h as HWND, WM_CLOSE, 0, 0);
                            }
                            emergency_restore();
                        }
                        let _ = rx.recv_timeout(std::time::Duration::from_secs(2));
                        return Err(if !appeared {
                            "the confirmation window did not open — switched back to the normal desktop".into()
                        } else {
                            "the confirmation window did not respond — switched back to the normal desktop".into()
                        });
                    }
                }
            }
        }
    }

    /// Owns the desktop switch; restoring happens on drop, including error and panic paths.
    struct DesktopGuard {
        prev: HDESK,
        desk: HDESK,
    }

    impl DesktopGuard {
        fn enter() -> Result<DesktopGuard, String> {
            unsafe {
                let prev = OpenInputDesktop(0, 0, 0x0100);
                let name = wide("KeyHolderSecure");
                let desk = CreateDesktopW(name.as_ptr(), null_mut(), null_mut(), 0, 0x02000000, null_mut());
                if desk.is_null() {
                    if !prev.is_null() {
                        CloseDesktop(prev);
                    }
                    return Err(format!("could not create the desktop (error {})", GetLastError()));
                }
                if SetThreadDesktop(desk) == 0 || SwitchDesktop(desk) == 0 {
                    CloseDesktop(desk);
                    if !prev.is_null() {
                        CloseDesktop(prev);
                    }
                    return Err(format!("could not switch the desktop (error {})", GetLastError()));
                }
                Ok(DesktopGuard { prev, desk })
            }
        }
    }

    impl Drop for DesktopGuard {
        fn drop(&mut self) {
            unsafe {
                if !self.prev.is_null() {
                    SwitchDesktop(self.prev);
                    CloseDesktop(self.prev);
                }
                CloseDesktop(self.desk);
            }
        }
    }

    fn layout(p: &Prompt) -> Layout {
        let facts_h = p.facts.len() as i32 * 32;
        let note_h = if p.agent_note.is_some() { 88 } else { 0 };
        let mut y = 26;
        let heading_y = y;
        let divider_y = y + 34;
        y = divider_y + 16;
        let facts_y = y;
        y += facts_h;
        let note_y = y + 4;
        y += note_h + 12;
        let phish_y = y;
        y += 150 + 18;
        let input1_y = y;
        y += 62;
        let mut input2_y = -1;
        if p.field == Field::PasswordOtp {
            input2_y = y;
            y += 62;
        }
        let height = y + 84;
        Layout {
            heading_y,
            divider_y,
            facts_y,
            note_y,
            note_h,
            phish_y,
            input1_y,
            input2_y,
            height: height.min(unsafe { GetSystemMetrics(SM_CYSCREEN) } - 40),
        }
    }

    unsafe fn make_font(size: i32, weight: i32, face: &str) -> HFONT {
        let f = wide(face);
        CreateFontW(-size, 0, 0, 0, weight, 0, 0, 0, 1, 3, 0, 5, 0, f.as_ptr())
    }

    // ---------- painting ----------

    struct Painter {
        hdc: *mut c_void,
    }

    impl Painter {
        unsafe fn text(&self, s: &str, x: i32, y: i32, w: i32, h: i32, color: u32, font: HFONT, flags: u32) {
            SelectObject(self.hdc, font as _);
            SetTextColor(self.hdc, color);
            SetBkMode(self.hdc, TRANSPARENT as i32);
            let mut r = RECT { left: x, top: y, right: x + w, bottom: y + h };
            let mut buf: Vec<u16> = s.encode_utf16().collect();
            DrawTextW(self.hdc, buf.as_mut_ptr(), buf.len() as i32, &mut r, flags);
        }

        unsafe fn fill(&self, r: RECT, brush: HBRUSH) {
            FillRect(self.hdc, &r, brush);
        }
    }

    unsafe fn paint(hwnd: HWND) {
        let mut ps: PAINTSTRUCT = std::mem::zeroed();
        let hdc = BeginPaint(hwnd, &mut ps);
        let g = UI.lock().unwrap_or_else(|e| e.into_inner());
        let Some(u) = g.as_ref() else {
            EndPaint(hwnd, &mut ps);
            return;
        };
        let p = Painter { hdc: hdc as *mut c_void };
        // The noise goes first and the rest of the painting is clipped around it: filling the box
        // first and drawing the noise after made the word area flash between frames.
        if let Some(n) = &u.noise {
            let r = word_rect(u.layout);
            let px = n.frame();
            let bmi = dib_info(n.w, n.h);
            StretchDIBits(
                hdc,
                r.left,
                r.top,
                n.w as i32 * CELL,
                n.h as i32 * CELL,
                0,
                0,
                n.w as i32,
                n.h as i32,
                px.as_ptr() as *const c_void,
                &bmi,
                DIB_RGB_COLORS,
                SRCCOPY,
            );
            ExcludeClipRect(hdc, r.left, r.top, r.left + n.w as i32 * CELL, r.top + n.h as i32 * CELL);
        }
        let mut rc: RECT = std::mem::zeroed();
        GetClientRect(hwnd, &mut rc);
        p.fill(rc, u.bg);

        let f_heading = u.fonts[0];
        let f_body = u.fonts[1];
        let f_button = u.fonts[2];
        let f_phish = u.fonts[3];
        let f_small = u.fonts[4];

        p.text(&u.heading, PAD, u.layout.heading_y, W - PAD * 2, 30, TEXT, f_heading, DT_LEFT | DT_SINGLELINE);
        p.fill(
            RECT { left: PAD, top: u.layout.divider_y, right: W - PAD, bottom: u.layout.divider_y + 1 },
            u.field_bg,
        );

        let mut y = u.layout.facts_y;
        for (label, value) in &u.facts {
            p.text(label, PAD, y, 168, 24, MUTED, f_small, DT_LEFT | DT_SINGLELINE);
            p.text(
                value,
                PAD + 176,
                y,
                W - PAD * 2 - 176,
                24,
                TEXT,
                f_body,
                DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            y += 32;
        }

        if let Some(note) = &u.note {
            p.text("From the agent:", PAD, u.layout.note_y, 220, 18, WARN, f_small, DT_LEFT | DT_SINGLELINE);
            p.text(note, PAD, u.layout.note_y + 20, W - PAD * 2, u.layout.note_h - 20, MUTED, f_body, DT_WORDBREAK);
        }

        // Anti-phishing word: painted glyph by glyph, so it is not text in the accessibility tree.
        let phish_box = RECT {
            left: PAD,
            top: u.layout.phish_y,
            right: W - PAD,
            bottom: u.layout.phish_y + 150,
        };
        p.fill(phish_box, u.field_bg);
        p.text(
            "anti-phishing word",
            PAD + 14,
            u.layout.phish_y + 8,
            280,
            18,
            MUTED,
            f_small,
            DT_LEFT | DT_SINGLELINE,
        );
        if u.noise.is_none() {
            let word_y = u.layout.phish_y + 70;
            let mut x = PAD + 14;
            for ch in u.antiphish.chars() {
                let s: String = ch.to_string();
                p.text(&s, x, word_y, 26, 28, ACCENT, f_phish, DT_LEFT | DT_SINGLELINE);
                x += 22;
            }
        }

        let (l1, l2) = labels(u.field);
        p.text(l1, PAD, u.layout.input1_y, 320, 18, MUTED, f_small, DT_LEFT | DT_SINGLELINE);
        if mask_password(u.field) {
            let r = peek_rect(u.layout);
            let label = if u.shown { "Hide" } else { "Show" };
            p.text(label, r.left, r.top + 2, r.right - r.left, 18, ACCENT, f_small, DT_RIGHT | DT_SINGLELINE);
        }
        if let Some(l2) = l2 {
            if u.layout.input2_y >= 0 {
                p.text(l2, PAD, u.layout.input2_y, 320, 18, MUTED, f_small, DT_LEFT | DT_SINGLELINE);
            }
        }
        let focused = GetFocus() as usize;
        for (y, edit) in [(u.layout.input1_y, u.edit1), (u.layout.input2_y, u.edit2)] {
            if y >= 0 {
                let brush = if edit != 0 && edit == focused { u.accent } else { u.frame };
                FrameRect(hdc, &field_rect(y), brush);
            }
        }

        // Buttons: drawn here, hit-tested in WM_LBUTTONDOWN (no WM_COMMAND to spoof).
        let (ok_r, cancel_r) = button_rects(u.layout);
        p.fill(cancel_r, u.field_bg);
        p.text("Deny", cancel_r.left, cancel_r.top, 160, 36, if u.armed { TEXT } else { MUTED }, f_button, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        p.fill(ok_r, if u.armed { u.accent } else { u.field_bg });
        p.text(
            "Allow",
            ok_r.left,
            ok_r.top,
            160,
            36,
            if u.armed { ON_ACCENT } else { MUTED },
            f_button,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE,
        );

        EndPaint(hwnd, &mut ps);
    }

    fn button_rects(l: Layout) -> (RECT, RECT) {
        let ok_right = W - PAD;
        let ok_left = ok_right - 160;
        let top = l.height - 60;
        (
            RECT { left: ok_left, top, right: ok_right, bottom: top + 36 },
            RECT { left: ok_left - 12 - 160, top, right: ok_left - 12, bottom: top + 36 },
        )
    }

    fn inside(r: RECT, x: i32, y: i32) -> bool {
        x >= r.left && x < r.right && y >= r.top && y < r.bottom
    }

    // ---------- window ----------

    unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
        match msg {
            WM_CREATE => {
                build_controls(hwnd);
                0
            }
            WM_PAINT => {
                paint(hwnd);
                0
            }
            WM_ERASEBKGND => 1,
            WM_CTLCOLOREDIT => {
                let g = UI.lock().unwrap_or_else(|e| e.into_inner());
                let hdc = w as *mut c_void;
                SetTextColor(hdc, TEXT);
                SetBkColor(hdc, BG);
                g.as_ref().map(|u| u.bg as LRESULT).unwrap_or(0)
            }
            WM_TIMER if w == TIMER_GIVE_UP => {
                finish(hwnd, false);
                0
            }
            WM_TIMER if w == TIMER_BEAT => {
                beat();
                0
            }
            WM_TIMER if w == TIMER_NOISE => {
                let area = {
                    let mut g = UI.lock().unwrap_or_else(|e| e.into_inner());
                    match g.as_mut() {
                        Some(u) => {
                            if let Some(n) = u.noise.as_mut() {
                                n.t = n.t.wrapping_add(1);
                            }
                            Some(word_rect(u.layout))
                        }
                        None => None,
                    }
                };
                if let Some(r) = area {
                    InvalidateRect(hwnd, &r, 0);
                }
                0
            }
            WM_COMMAND => {
                // IsDialogMessage turns Esc inside an edit field into IDCANCEL.
                if (w & 0xffff) == 2 {
                    finish(hwnd, false);
                }
                // EN_SETFOCUS / EN_KILLFOCUS: repaint the field frames.
                if matches!((w >> 16) & 0xffff, 0x0100 | 0x0200) {
                    InvalidateRect(hwnd, null_mut(), 0);
                }
                0
            }
            WM_TIMER => {
                // Take what is needed and release UI before calling Win32: SetFocus sends
                // messages back into this procedure, which locks UI again (same thread).
                let focus = {
                    let mut g = UI.lock().unwrap_or_else(|e| e.into_inner());
                    match g.as_mut() {
                        Some(u) => {
                            u.armed = true;
                            u.focus
                        }
                        None => 0,
                    }
                };
                KillTimer(hwnd, TIMER_ARM);
                if cfg!(debug_assertions) && TEST_HANG.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_secs(30));
                }
                if focus != 0 {
                    SetFocus(focus as HWND);
                }
                InvalidateRect(hwnd, null_mut(), 0);
                0
            }
            WM_LBUTTONDOWN => {
                let x = (l & 0xffff) as i16 as i32;
                let y = ((l >> 16) & 0xffff) as i16 as i32;
                // Peek at the typed password: toggle the edit's password character.
                let peek = {
                    let mut g = UI.lock().unwrap_or_else(|e| e.into_inner());
                    match g.as_mut() {
                        Some(u) if mask_password(u.field) && inside(peek_rect(u.layout), x, y) => {
                            u.shown = !u.shown;
                            Some((u.edit1, u.shown))
                        }
                        _ => None,
                    }
                };
                if let Some((edit, shown)) = peek {
                    const EM_SETPASSWORDCHAR: u32 = 0x00CC;
                    SendMessageW(edit as HWND, EM_SETPASSWORDCHAR, if shown { 0 } else { 0x25CF }, 0);
                    InvalidateRect(edit as HWND, null_mut(), 1);
                    InvalidateRect(hwnd, null_mut(), 0);
                    return 0;
                }
                let action = {
                    let g = UI.lock().unwrap_or_else(|e| e.into_inner());
                    match g.as_ref() {
                        Some(u) if u.armed => {
                            let (ok_r, cancel_r) = button_rects(u.layout);
                            if inside(ok_r, x, y) {
                                Some(true)
                            } else if inside(cancel_r, x, y) {
                                Some(false)
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                };
                if let Some(ok) = action {
                    finish(hwnd, ok);
                }
                0
            }
            WM_KEYDOWN => {
                if w as u32 == VK_ESCAPE as u32 {
                    finish(hwnd, false);
                }
                0
            }
            WM_CLOSE => {
                finish(hwnd, false);
                0
            }
            WM_DESTROY => {
                KillTimer(hwnd, TIMER_ARM);
                KillTimer(hwnd, TIMER_GIVE_UP);
                KillTimer(hwnd, TIMER_BEAT);
                KillTimer(hwnd, TIMER_NOISE);
                CURRENT_HWND.store(0, std::sync::atomic::Ordering::SeqCst);
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, w, l),
        }
    }

    unsafe fn finish(hwnd: HWND, ok: bool) {
        // Reading the fields sends messages to the edit controls: do it with UI released.
        let edits = {
            let g = UI.lock().unwrap_or_else(|e| e.into_inner());
            g.as_ref().map(|u| (u.edit1, u.edit2))
        };
        let answer = match edits {
            Some((e1, e2)) if ok => Some(Answer {
                first: read_edit(e1 as HWND),
                second: if e2 == 0 { String::new() } else { read_edit(e2 as HWND) },
            }),
            _ => None,
        };
        {
            let mut g = UI.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(u) = g.as_mut() {
                u.answer = answer;
            }
        }
        DestroyWindow(hwnd);
    }

    unsafe fn read_edit(h: HWND) -> String {
        if h.is_null() {
            return String::new();
        }
        let n = GetWindowTextLengthW(h);
        if n <= 0 {
            return String::new();
        }
        let mut buf = vec![0u16; (n + 1) as usize];
        let got = GetWindowTextW(h, buf.as_mut_ptr(), n + 1);
        String::from_utf16_lossy(&buf[..got.max(0) as usize])
    }

    unsafe fn build_controls(hwnd: HWND) {
        // Timers first: even if anything below goes wrong, the prompt still cancels itself.
        SetTimer(hwnd, TIMER_ARM, 1000, None);
        SetTimer(hwnd, TIMER_GIVE_UP, give_up_ms(), None);
        SetTimer(hwnd, TIMER_BEAT, BEAT_MS, None);
        beat();
        // Copy what is needed and release UI: creating controls and moving focus send messages
        // back into wndproc, which locks UI too — holding it here deadlocked the window before it
        // ever appeared (black desktop, cursor only).
        let (field, layout, font, noise) = {
            let g = UI.lock().unwrap_or_else(|e| e.into_inner());
            match g.as_ref() {
                Some(u) => (u.field, u.layout, u.fonts[1], u.noise.is_some()),
                None => return,
            }
        };
        if noise {
            SetTimer(hwnd, TIMER_NOISE, NOISE_MS, None);
        }
        let hinst = GetModuleHandleW(null_mut());
        let pass_style = if mask_password(field) { 0x0020 } else { 0 }; // ES_PASSWORD
        let class = wide("EDIT");
        let make = |id: i32, y: i32| -> HWND {
            let e = CreateWindowExW(
                0,
                class.as_ptr(),
                wide("").as_ptr(),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | pass_style | 0x0080, // ES_AUTOHSCROLL
                PAD + 10,
                field_rect(y).top + 6,
                W - PAD * 2 - 20,
                20,
                hwnd,
                id as usize as *mut c_void,
                hinst,
                null_mut(),
            );
            SendMessageW(e, 0x00C5, 64, 0); // EM_SETLIMITTEXT
            SendMessageW(e, WM_SETFONT, font as usize, 0);
            e
        };
        let e1 = make(ID_EDIT1, layout.input1_y);
        let e2 = if layout.input2_y >= 0 { make(ID_EDIT2, layout.input2_y) } else { null_mut() };
        {
            let mut g = UI.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(u) = g.as_mut() {
                u.edit1 = e1 as usize;
                u.edit2 = e2 as usize;
                u.focus = e1 as usize;
            }
        }
        SetFocus(e1);
    }

    fn run(p: Prompt) -> Result<Answer, String> {
        let layout = layout(&p);
        // A previous prompt that never finished still holds the state: refuse before touching
        // the screen rather than switch to a desktop nobody can draw on.
        if UI.try_lock().is_err() {
            return Err("the previous confirmation window has not closed yet".into());
        }
        let _desktop = match TEST_NO_SWITCH.load(std::sync::atomic::Ordering::Relaxed) {
            true => None,
            false => Some(DesktopGuard::enter()?),
        };
        unsafe {
            let hinst = GetModuleHandleW(null_mut());
            let class_name = wide("KeyHolderSecureWindow");
            let wc = WNDCLASSW {
                style: 0,
                lpfnWndProc: Some(wndproc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: hinst,
                hIcon: null_mut(),
                hCursor: LoadCursorW(null_mut(), IDC_ARROW),
                hbrBackground: null_mut(),
                lpszMenuName: null_mut(),
                lpszClassName: class_name.as_ptr(),
            };
            RegisterClassW(&wc);

            {
                let mut g = UI.lock().unwrap_or_else(|e| e.into_inner());
                let noise = if p.noise { Noise::new(&p.antiphish, word_rect(layout)) } else { None };
                *g = Some(Ui {
                    heading: p.heading,
                    facts: p.facts,
                    note: p.agent_note,
                    antiphish: p.antiphish,
                    field: p.field,
                    hwnd: 0,
                    edit1: 0,
                    edit2: 0,
                    fonts: vec![
                        make_font(21, 600, "Segoe UI Semibold"),
                        make_font(14, 400, "Segoe UI"),
                        make_font(14, 600, "Segoe UI Semibold"),
                        make_font(24, 700, "Segoe UI"),
                        make_font(12, 400, "Segoe UI"),
                    ],
                    bg: CreateSolidBrush(BG),
                    field_bg: CreateSolidBrush(BORDER),
                    accent: CreateSolidBrush(ACCENT),
                    frame: CreateSolidBrush(FRAME),
                    layout,
                    answer: None,
                    armed: false,
                    focus: 0,
                    shown: false,
                    noise,
                });
            }

            // The layout is in client coordinates; the window adds the caption and borders.
            let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE | WS_CLIPCHILDREN;
            let ex_style = WS_EX_TOPMOST | WS_EX_APPWINDOW;
            let mut outer = RECT { left: 0, top: 0, right: W, bottom: layout.height };
            AdjustWindowRectEx(&mut outer, style, 0, ex_style);
            let (ow, oh) = (outer.right - outer.left, outer.bottom - outer.top);
            let sw = GetSystemMetrics(SM_CXSCREEN);
            let sh = GetSystemMetrics(SM_CYSCREEN);
            let x = (sw - ow) / 2;
            let y = ((sh - oh) / 2).max(20);
            let title = wide("MCP Keyholder — confirmation");
            let hwnd = CreateWindowExW(
                ex_style,
                class_name.as_ptr(),
                title.as_ptr(),
                style,
                x,
                y,
                ow,
                oh,
                null_mut(),
                null_mut(),
                hinst,
                null_mut(),
            );
            if hwnd.is_null() {
                let code = GetLastError();
                clear_state();
                return Err(format!("could not create the window (error {code})"));
            }
            {
                let mut g = UI.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(u) = g.as_mut() {
                    u.hwnd = hwnd as usize;
                }
            }
            CURRENT_HWND.store(hwnd as usize, std::sync::atomic::Ordering::SeqCst);
            APPEARED.store(true, std::sync::atomic::Ordering::SeqCst);
            // Screen capture gets a black box instead of the window (the anti-phishing word must
            // not end up in a screenshot). Debug builds stay capturable for design review.
            if !cfg!(debug_assertions) {
                SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);
            }
            ShowWindow(hwnd, SW_SHOW);
            UpdateWindow(hwnd);
            InvalidateRect(hwnd, null_mut(), 1);

            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
                if IsDialogMessageW(hwnd, &msg) == 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }

            let answer = clear_state();
            match answer {
                Some(a) if !a.first.trim().is_empty() => Ok(a),
                Some(_) => Err("empty input".into()),
                None => Err("cancelled".into()),
            }
        }
    }

    /// Drops the window state and frees GDI objects; returns what the human confirmed.
    unsafe fn clear_state() -> Option<Answer> {
        let mut g = UI.lock().unwrap_or_else(|e| e.into_inner());
        let answer = g.as_mut().and_then(|u| u.answer.take());
        if let Some(u) = g.as_mut() {
            for f in u.fonts.drain(..) {
                DeleteObject(f as _);
            }
            DeleteObject(u.bg as _);
            DeleteObject(u.field_bg as _);
            DeleteObject(u.accent as _);
            DeleteObject(u.frame as _);
        }
        *g = None;
        answer
    }

    #[allow(dead_code)]
    fn _point_layout_check() {
        // Keeps POINT in use for future hit-testing of the input area.
        let _ = POINT { x: 0, y: 0 };
    }
}
