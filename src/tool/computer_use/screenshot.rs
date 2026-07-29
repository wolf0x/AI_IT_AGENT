//! Screen capture via DXGI Desktop Duplication (GPU) with GDI BitBlt fallback.
//! Pure Rust, Windows-only, no external processes.

use std::sync::Mutex;
use windows::core::Interface;
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Direct3D::*;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Graphics::Dxgi::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::UI::WindowsAndMessaging::*;

pub struct ScreenshotResult {
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub mime_type: &'static str,
}

// ── Cached DXGI resources ────────────────────────────────────────────

struct DxgiCapture {
    context: ID3D11DeviceContext,
    duplication: IDXGIOutputDuplication,
    staging: ID3D11Texture2D,
    staging_res: ID3D11Resource,
    width: u32,
    height: u32,
}

unsafe impl Send for DxgiCapture {}

static DXGI_CACHE: Mutex<Option<DxgiCapture>> = Mutex::new(None);

fn init_dxgi() -> Result<DxgiCapture, String> {
    unsafe {
        let mut device: Option<ID3D11Device> = None;
        let mut context: Option<ID3D11DeviceContext> = None;
        D3D11CreateDevice(
            None,
            D3D_DRIVER_TYPE_HARDWARE,
            None,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            Some(&[D3D_FEATURE_LEVEL_11_0]),
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )
        .map_err(|e| format!("D3D11CreateDevice: {e}"))?;

        let device = device.ok_or("No D3D11 device")?;
        let context = context.ok_or("No D3D11 context")?;

        let dxgi_device: IDXGIDevice = device.cast().map_err(|e| format!("IDXGIDevice: {e}"))?;
        let adapter: IDXGIAdapter = dxgi_device.GetParent().map_err(|e| format!("adapter: {e}"))?;
        let output: IDXGIOutput = adapter.EnumOutputs(0).map_err(|e| format!("EnumOutputs: {e}"))?;
        let output1: IDXGIOutput1 = output.cast().map_err(|e| format!("IDXGIOutput1: {e}"))?;
        let duplication = output1
            .DuplicateOutput(&device)
            .map_err(|e| format!("DuplicateOutput: {e}"))?;

        let desc = duplication.GetDesc();
        let w = desc.ModeDesc.Width;
        let h = desc.ModeDesc.Height;

        let tex_desc = D3D11_TEXTURE2D_DESC {
            Width: w,
            Height: h,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
        };
        let mut staging: Option<ID3D11Texture2D> = None;
        device
            .CreateTexture2D(&tex_desc, None, Some(&mut staging))
            .map_err(|e| format!("staging texture: {e}"))?;
        let staging = staging.ok_or("staging None")?;
        let staging_res: ID3D11Resource = staging.cast().map_err(|e| format!("staging resource: {e}"))?;

        // Warm up: acquire the FIRST frame (always available right after DuplicateOutput,
        // even on a static desktop) and copy it into the staging texture. This gives us a
        // valid baseline so that later timeouts (static desktop) still yield real content
        // instead of reading an uninitialized (black) staging texture.
        let mut fi = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut res: Option<IDXGIResource> = None;
        for _ in 0..10 {
            match duplication.AcquireNextFrame(300, &mut fi, &mut res) {
                Ok(()) => {
                    if let Some(ref r) = res {
                        if let Ok(texture) = r.cast::<ID3D11Texture2D>() {
                            if let Ok(tex_res) = texture.cast::<ID3D11Resource>() {
                                context.CopyResource(&staging_res, &tex_res);
                            }
                        }
                    }
                    let _ = duplication.ReleaseFrame();
                    break;
                }
                Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => continue,
                Err(_) => break,
            }
        }

        Ok(DxgiCapture { context, duplication, staging, staging_res, width: w, height: h })
    }
}

fn capture_screen_dxgi() -> Result<(Vec<u8>, u32, u32), String> {
    let mut cache = DXGI_CACHE.lock().map_err(|e| format!("lock: {e}"))?;
    if cache.is_none() {
        *cache = Some(init_dxgi()?);
    }
    let cap = cache.as_ref().unwrap();

    unsafe {
        let mut fi = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;

        let mut got_frame = false;
        for _ in 0..3 {
            match cap.duplication.AcquireNextFrame(100, &mut fi, &mut resource) {
                Ok(()) => { got_frame = true; break; }
                Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => continue,
                Err(e) => { *cache = None; return Err(format!("AcquireNextFrame: {e}")); }
            }
        }

        if got_frame {
            if let Some(ref res) = resource {
                let texture: ID3D11Texture2D = res.cast().map_err(|e| format!("Texture2D: {e}"))?;
                let tex_res: ID3D11Resource = texture.cast().map_err(|e| format!("tex resource: {e}"))?;
                cap.context.CopyResource(&cap.staging_res, &tex_res);
            }
            let _ = cap.duplication.ReleaseFrame();
        }

        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        cap.context
            .Map(&cap.staging_res, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
            .map_err(|e| format!("Map: {e}"))?;

        let row_pitch = mapped.RowPitch as usize;
        let w = cap.width;
        let h = cap.height;
        let mut pixels = Vec::with_capacity((w * h * 4) as usize);
        let src = mapped.pData as *const u8;
        for y in 0..h as usize {
            let row = std::slice::from_raw_parts(src.add(y * row_pitch), w as usize * 4);
            pixels.extend_from_slice(row);
        }
        cap.context.Unmap(&cap.staging_res, 0);
        Ok((pixels, w, h))
    }
}

// ── GDI BitBlt fallback ──────────────────────────────────────────────

/// Capture a rectangle (in the source DC's coordinate space) via GDI BitBlt.
/// Shared by full-screen and per-window capture.
unsafe fn capture_rect_from_dc(
    hdc_src: HDC,
    src_x: i32,
    src_y: i32,
    w: u32,
    h: u32,
) -> Result<(Vec<u8>, u32, u32), String> {
    let hdc_mem = CreateCompatibleDC(hdc_src);
    let hbm = CreateCompatibleBitmap(hdc_src, w as i32, h as i32);
    let old = SelectObject(hdc_mem, hbm);
    let _ = BitBlt(hdc_mem, 0, 0, w as i32, h as i32, hdc_src, src_x, src_y, SRCCOPY);

    let mut bmi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: w as i32,
            biHeight: -(h as i32),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut pixels = vec![0u8; (w * h * 4) as usize];
    GetDIBits(hdc_mem, hbm, 0, h, Some(pixels.as_mut_ptr() as *mut _), &mut bmi, DIB_RGB_COLORS);

    SelectObject(hdc_mem, old);
    let _ = DeleteObject(hbm);
    let _ = DeleteDC(hdc_mem);
    Ok((pixels, w, h))
}

fn capture_screen_gdi() -> Result<(Vec<u8>, u32, u32), String> {
    unsafe {
        let hdc_screen = GetDC(None);
        if hdc_screen.is_invalid() {
            return Err("GetDC failed".into());
        }
        let w = GetSystemMetrics(SM_CXSCREEN) as u32;
        let h = GetSystemMetrics(SM_CYSCREEN) as u32;
        let result = capture_rect_from_dc(hdc_screen, 0, 0, w, h);
        ReleaseDC(None, hdc_screen);
        result
    }
}

/// Capture a specific window by HWND via GDI BitBlt.
///
/// First tries the window's own device context. This works for classic GDI
/// windows (and for occluded/minimized ones), but returns BLACK for
/// hardware-accelerated windows — Electron/Chromium apps (Qoder, VS Code,
/// browsers) and video players render via DirectComposition, so their window
/// DC is empty. When that happens, fall back to capturing the region of the
/// SCREEN where the window is displayed: the DWM-composited desktop surface
/// DOES contain the hardware-accelerated content.
fn capture_window(hwnd_val: isize) -> Result<(Vec<u8>, u32, u32), String> {
    unsafe {
        let hwnd = HWND(hwnd_val as *mut _);
        let mut rect = RECT::default();
        let _ = GetWindowRect(hwnd, &mut rect);
        let w = (rect.right - rect.left).max(1) as u32;
        let h = (rect.bottom - rect.top).max(1) as u32;

        // Attempt 1: the window's own DC.
        let hdc_win = GetDC(hwnd);
        let window_dc_result = if hdc_win.is_invalid() {
            Err("GetDC for window failed".to_string())
        } else {
            let r = capture_rect_from_dc(hdc_win, 0, 0, w, h);
            ReleaseDC(hwnd, hdc_win);
            r
        };

        // Use the window-DC image if it contains real (non-black) content.
        let window_dc_usable = match &window_dc_result {
            Ok((px, _, _)) => !is_mostly_black(px),
            Err(_) => false,
        };
        if window_dc_usable {
            return window_dc_result;
        }

        // Attempt 2: capture the on-screen region occupied by the window from
        // the screen DC — picks up DirectComposition/hardware-accelerated
        // content that the window DC cannot provide.
        let hdc_screen = GetDC(None);
        if hdc_screen.is_invalid() {
            // No screen DC; return whatever the window DC produced.
            return window_dc_result;
        }
        let screen_result = capture_rect_from_dc(hdc_screen, rect.left, rect.top, w, h);
        ReleaseDC(None, hdc_screen);
        screen_result
    }
}

// ── Pixel processing ─────────────────────────────────────────────────

/// Area-averaging box-filter downscale on BGRA pixels.
fn resize_bgra_box(src: &[u8], sw: u32, sh: u32, dw: u32, dh: u32) -> Vec<u8> {
    let mut dst = vec![0u8; (dw * dh * 4) as usize];
    let x_ratio = sw as f64 / dw as f64;
    let y_ratio = sh as f64 / dh as f64;
    for dy in 0..dh {
        let sy_start = (dy as f64 * y_ratio) as u32;
        let sy_end = (((dy + 1) as f64 * y_ratio) as u32).min(sh);
        let y_count = (sy_end - sy_start).max(1) as u32;
        for dx in 0..dw {
            let sx_start = (dx as f64 * x_ratio) as u32;
            let sx_end = (((dx + 1) as f64 * x_ratio) as u32).min(sw);
            let x_count = (sx_end - sx_start).max(1) as u32;
            let area = (x_count * y_count) as u32;
            let (mut r_sum, mut g_sum, mut b_sum) = (0u32, 0u32, 0u32);
            for sy in sy_start..sy_end {
                let row_off = (sy * sw * 4) as usize;
                for sx in sx_start..sx_end {
                    let si = row_off + (sx * 4) as usize;
                    b_sum += src[si] as u32;
                    g_sum += src[si + 1] as u32;
                    r_sum += src[si + 2] as u32;
                }
            }
            let di = ((dy * dw + dx) * 4) as usize;
            dst[di] = (b_sum / area) as u8;
            dst[di + 1] = (g_sum / area) as u8;
            dst[di + 2] = (r_sum / area) as u8;
            dst[di + 3] = 255;
        }
    }
    dst
}

/// Convert BGRA to RGB.
fn bgra_to_rgb(bgra: &[u8]) -> Vec<u8> {
    let pixel_count = bgra.len() / 4;
    let mut rgb = Vec::with_capacity(pixel_count * 3);
    for chunk in bgra.chunks_exact(4) {
        rgb.push(chunk[2]); // R
        rgb.push(chunk[1]); // G
        rgb.push(chunk[0]); // B
    }
    rgb
}

/// Detect whether a BGRA frame is (nearly) all black.
/// DXGI Desktop Duplication returns black frames when the wrong GPU adapter is
/// used (hybrid iGPU/dGPU systems), the desktop is locked/protected, or the
/// staging texture was never populated. Sampling every 64th pixel keeps this cheap.
fn is_mostly_black(bgra: &[u8]) -> bool {
    if bgra.len() < 4 {
        return true;
    }
    let mut sampled = 0usize;
    let mut black = 0usize;
    for chunk in bgra.chunks_exact(4).step_by(64) {
        sampled += 1;
        // Sum of B+G+R < 24 (~8 per channel) counts as black
        if (chunk[0] as u32 + chunk[1] as u32 + chunk[2] as u32) < 24 {
            black += 1;
        }
    }
    if sampled == 0 {
        return true;
    }
    (black as f64 / sampled as f64) > 0.99
}

fn encode_png(rgb: &[u8], w: u32, h: u32) -> Result<Vec<u8>, String> {
    use image::codecs::png::PngEncoder;
    use image::ImageEncoder;
    let mut buf = std::io::Cursor::new(Vec::with_capacity((w * h * 3 / 2) as usize));
    let enc = PngEncoder::new(&mut buf);
    enc.write_image(rgb, w, h, image::ExtendedColorType::Rgb8)
        .map_err(|e| format!("PNG encode: {e}"))?;
    Ok(buf.into_inner())
}

fn encode_jpeg(rgb: &[u8], w: u32, h: u32, quality: u8) -> Result<Vec<u8>, String> {
    use image::codecs::jpeg::JpegEncoder;
    use image::ImageEncoder;
    let mut buf = std::io::Cursor::new(Vec::with_capacity((w * h * 3 / 4) as usize));
    let mut enc = JpegEncoder::new_with_quality(&mut buf, quality);
    enc.encode(rgb, w, h, image::ExtendedColorType::Rgb8)
        .map_err(|e| format!("JPEG encode: {e}"))?;
    Ok(buf.into_inner())
}

// ── Public API ───────────────────────────────────────────────────────

/// Take a screenshot. Returns encoded image bytes.
/// - `width`: target width for downscale (None = native resolution)
/// - `quality`: 0 = PNG, 1-100 = JPEG quality (default 80)
/// - `window_id`: optional HWND to capture a specific window
pub fn take_screenshot(
    width: Option<u32>,
    quality: Option<u32>,
    window_id: Option<isize>,
) -> Result<ScreenshotResult, String> {
    let (pixels, mut w, mut h) = if let Some(wid) = window_id {
        capture_window(wid)?
    } else {
        // Try DXGI (fast, GPU) first. If it fails OR returns a black frame
        // (wrong adapter / protected desktop / unpopulated staging), fall back
        // to GDI BitBlt which reliably captures the interactive desktop.
        match capture_screen_dxgi() {
            Ok((px, pw, ph)) if !is_mostly_black(&px) => (px, pw, ph),
            _ => capture_screen_gdi()?,
        }
    };

    // Resize on BGRA then convert to RGB
    let rgb = if let Some(target_w) = width {
        if target_w < w && target_w > 0 {
            let target_h = (h as u64 * target_w as u64 / w as u64) as u32;
            let resized = resize_bgra_box(&pixels, w, h, target_w, target_h);
            w = target_w;
            h = target_h;
            bgra_to_rgb(&resized)
        } else {
            bgra_to_rgb(&pixels)
        }
    } else {
        bgra_to_rgb(&pixels)
    };

    let q = quality.unwrap_or(80);
    let (data, mime_type) = if q == 0 {
        (encode_png(&rgb, w, h)?, "image/png")
    } else {
        (encode_jpeg(&rgb, w, h, q.clamp(1, 100) as u8)?, "image/jpeg")
    };

    Ok(ScreenshotResult { data, width: w, height: h, mime_type })
}
