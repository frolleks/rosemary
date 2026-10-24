#![allow(non_snake_case)]

//! `CGContext`: the graphics state and drawing calls, over the engine in
//! `crate::quartz`.

use std::ffi::c_void;

use crate::{CGAffineTransformIdentity, CGPoint, CGRect, CGSize};
use corefoundation::base::CFTypeRef;
use tiny_skia as sk;

use crate::cgpath::Elements;
use crate::quartz::{self, BitmapContext, Ink, Retained, State, context_of, state_of};
use crate::{CGAffineTransformMakeScale, CGAffineTransformMakeTranslation};

pub use crate::CGAffineTransform;

pub type CGContextRef = CFTypeRef;

#[repr(C)]
struct Color {
    isa: *const c_void,
    components: [f64; 4],
}

pub fn install() {
    let context =
        corefoundation::base::register(c"__CGContext", None, size_of::<BitmapContext>(), true);
    context.replace_method(
        objc::sel::get("dealloc"),
        context_dealloc as *const c_void,
        c"v16@0:8",
    );
    corefoundation::base::register(c"__CGColor", None, size_of::<Color>(), true);
    crate::cgpaint::install();
}

unsafe extern "C" fn context_dealloc(receiver: objc::object::Id, _sel: objc::sel::Sel) {
    // SAFETY: `-dealloc` of a `__CGContext`, whose state came from `Box::into_raw`.
    unsafe {
        let context = &mut *(receiver as *mut BitmapContext);
        if !context.state.is_null() {
            drop(Box::from_raw(context.state));
            context.state = std::ptr::null_mut();
        }
        objc::arc::finalize(receiver);
    }
}

/// `kCGImageAlphaOnly`.
const ALPHA_ONLY: u32 = 7;

pub unsafe extern "C" fn CGBitmapContextCreate(
    data: *mut c_void,
    width: usize,
    height: usize,
    bits_per_component: usize,
    bytes_per_row: usize,
    space: CFTypeRef,
    bitmap_info: u32,
) -> CFTypeRef {
    if width == 0 || height == 0 || bits_per_component != 8 {
        return std::ptr::null();
    }
    let alpha = bitmap_info & quartz::ALPHA_INFO_MASK;
    let alpha_only = alpha == ALPHA_ONLY;
    // No space is RGB here unless the alpha is all there is.
    let components = crate::graphics::space_components(space).unwrap_or(3);
    let channels = match (alpha_only, components, alpha) {
        (true, _, _) => 1,
        (false, 1, 0) => 1,
        (false, 3, _) => 4,
        // Gray with alpha, CMYK and the like: refused, as Quartz refuses an
        // unsupported combination, rather than drawn in the wrong layout.
        _ => return std::ptr::null(),
    };
    let bytes_per_row = match bytes_per_row {
        0 => width * channels,
        n => n,
    };
    if bytes_per_row < width * channels {
        return std::ptr::null();
    }
    let mut owned = data.is_null().then(|| vec![0u8; bytes_per_row * height]);
    let data = owned
        .as_mut()
        .map_or(data.cast::<u8>(), |buffer| buffer.as_mut_ptr());
    let class = objc::class::lookup(c"__CGContext").expect("installed during bootstrap");
    // SAFETY: `BitmapContext` is the registered class layout.
    let context = unsafe { corefoundation::base::allocate::<BitmapContext>(class) };
    // SAFETY: a fresh allocation; the pixel storage is the caller's or owned
    // by the state, which lives as long as the context.
    unsafe {
        (*context).data = data;
        (*context).width = width;
        (*context).height = height;
        (*context).bytes_per_row = bytes_per_row;
        (*context).bits_per_component = bits_per_component;
        (*context).bitmap_info = bitmap_info;
        (*context).channels = channels;
        (*context).alpha_only = alpha_only;
        (*context).state = Box::into_raw(Box::new(State::new(owned)));
    }
    context as CFTypeRef
}

thread_local! {
    /// The focus context, and the focus it was last answered for.
    static FOCUS_CONTEXT: std::cell::Cell<(usize, Option<(usize, usize)>)> =
        const { std::cell::Cell::new((0, None)) };
}

/// The `CGContextRef` of the view being drawn, or null with nothing focused.
///
/// One per thread, its graphics state reset whenever the focus changes, since
/// AppKit hands each `-drawRect:` a fresh state. Its user space is the view's
/// own, in points, so drawing lands where the same rectangle would through
/// `NSImage`.
pub fn focus_context() -> CFTypeRef {
    let Some(device) = crate::focus::device() else {
        return std::ptr::null();
    };
    let focus = Some((device.key, device.depth));
    let (mut context, last) = FOCUS_CONTEXT.with(|cell| cell.get());
    if context == 0 {
        let class = objc::class::lookup(c"__CGContext").expect("installed during bootstrap");
        // SAFETY: `BitmapContext` is the registered class layout; the object
        // lives for the thread, so it is never released.
        let fresh = unsafe { corefoundation::base::allocate::<BitmapContext>(class) };
        unsafe {
            (*fresh).focus = true;
            (*fresh).channels = 4;
            (*fresh).state = Box::into_raw(Box::new(State::new(None)));
        }
        context = fresh as usize;
    } else if last != focus {
        // SAFETY: the context made above, whose state is never freed.
        let state = unsafe { &mut *(*(context as *mut BitmapContext)).state };
        *state = State::new(None);
    }
    FOCUS_CONTEXT.with(|cell| cell.set((context, focus)));
    context as CFTypeRef
}

pub unsafe extern "C" fn CGBitmapContextGetData(context: CFTypeRef) -> *mut c_void {
    context_of(context).map_or(std::ptr::null_mut(), |context| context.data.cast())
}

pub unsafe extern "C" fn CGBitmapContextGetWidth(context: CFTypeRef) -> usize {
    context_of(context).map_or(0, |context| context.width)
}

pub unsafe extern "C" fn CGBitmapContextGetHeight(context: CFTypeRef) -> usize {
    context_of(context).map_or(0, |context| context.height)
}

/// `CGImageRef CGBitmapContextCreateImage(CGContextRef)`: a copy of the
/// pixels as they are now, so later drawing does not show through.
pub unsafe extern "C" fn CGBitmapContextCreateImage(context: CFTypeRef) -> CFTypeRef {
    let Some(ctx) = context_of(context) else {
        return std::ptr::null();
    };
    let Some(pixels) = quartz::snapshot_bgra(ctx) else {
        return std::ptr::null();
    };
    // A gray context's image has no alpha to read as coverage; every other
    // layout's does, an alpha-only one's being all it has.
    let info = match ctx.channels == 1 && !ctx.alpha_only {
        true => 6 | quartz::BYTE_ORDER_32_LITTLE,
        false => crate::graphics::PREMULTIPLIED_BGRA,
    };
    crate::graphics::image_from_pixels(pixels, ctx.width, ctx.height, ctx.width * 4, info)
}

pub unsafe extern "C" fn CGBitmapContextGetBitmapInfo(context: CFTypeRef) -> u32 {
    context_of(context).map_or(0, |context| context.bitmap_info)
}

pub unsafe extern "C" fn CGBitmapContextGetBitsPerComponent(context: CFTypeRef) -> usize {
    context_of(context).map_or(0, |context| context.bits_per_component)
}

pub unsafe extern "C" fn CGBitmapContextGetBitsPerPixel(context: CFTypeRef) -> usize {
    context_of(context).map_or(0, |context| context.channels * 8)
}

pub unsafe extern "C" fn CGBitmapContextGetBytesPerRow(context: CFTypeRef) -> usize {
    context_of(context).map_or(0, |context| context.bytes_per_row)
}

/// The context's space, which the caller does not own: device gray for a
/// gray context, none for an alpha-only one, and device RGB otherwise.
pub unsafe extern "C" fn CGBitmapContextGetColorSpace(context: CFTypeRef) -> CFTypeRef {
    static RGB: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    static GRAY: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let Some(ctx) = context_of(context) else {
        return std::ptr::null();
    };
    // SAFETY: fresh spaces, kept for the process.
    let space = match (ctx.channels, ctx.alpha_only) {
        (1, true) => return std::ptr::null(),
        (1, false) => *GRAY
            .get_or_init(|| unsafe { crate::graphics::CGColorSpaceCreateDeviceGray() as usize }),
        _ => {
            *RGB.get_or_init(|| unsafe { crate::graphics::CGColorSpaceCreateDeviceRGB() as usize })
        }
    };
    space as CFTypeRef
}

pub unsafe extern "C" fn CGContextRetain(context: CFTypeRef) -> CFTypeRef {
    if context.is_null() {
        return context;
    }
    unsafe { corefoundation::api::CFRetain(context) }
}

pub unsafe extern "C" fn CGContextRelease(context: CFTypeRef) {
    if !context.is_null() {
        unsafe { corefoundation::api::CFRelease(context) };
    }
}

pub unsafe extern "C" fn CGContextSaveGState(context: CFTypeRef) {
    if let Some(state) = state_of(context) {
        state.saved.push(state.current.clone());
    }
}

pub unsafe extern "C" fn CGContextRestoreGState(context: CFTypeRef) {
    if let Some(state) = state_of(context)
        && let Some(saved) = state.saved.pop()
    {
        state.current = saved;
    }
}

fn gstate<'a>(context: CFTypeRef) -> Option<&'a mut quartz::GState> {
    state_of(context).map(|state| &mut state.current)
}

pub unsafe extern "C" fn CGContextConcatCTM(context: CFTypeRef, transform: CGAffineTransform) {
    if let Some(state) = gstate(context) {
        state.ctm = transform.then(state.ctm);
    }
}

pub unsafe extern "C" fn CGContextGetCTM(context: CFTypeRef) -> CGAffineTransform {
    gstate(context).map_or(CGAffineTransformIdentity, |state| state.ctm)
}

/// `CGContextSetCTM`, private but exported, and used by Cairo to put back a
/// transform it read with `CGContextGetCTM`.
pub unsafe extern "C" fn CGContextSetCTM(context: CFTypeRef, transform: CGAffineTransform) {
    if let Some(state) = gstate(context) {
        state.ctm = transform;
    }
}

pub unsafe extern "C" fn CGContextTranslateCTM(context: CFTypeRef, x: f64, y: f64) {
    unsafe { CGContextConcatCTM(context, CGAffineTransformMakeTranslation(x, y)) };
}

pub unsafe extern "C" fn CGContextScaleCTM(context: CFTypeRef, x: f64, y: f64) {
    unsafe { CGContextConcatCTM(context, CGAffineTransformMakeScale(x, y)) };
}

pub unsafe extern "C" fn CGContextRotateCTM(context: CFTypeRef, angle: f64) {
    let (sin, cos) = angle.sin_cos();
    let rotation = CGAffineTransform {
        a: cos,
        b: sin,
        c: -sin,
        d: cos,
        ..CGAffineTransformIdentity
    };
    unsafe { CGContextConcatCTM(context, rotation) };
}

//
// Colours
//

pub unsafe extern "C" fn CGContextSetRGBFillColor(
    context: CFTypeRef,
    red: f64,
    green: f64,
    blue: f64,
    alpha: f64,
) {
    if let Some(state) = gstate(context) {
        state.fill = Ink::Color([red, green, blue, alpha]);
    }
}

pub unsafe extern "C" fn CGContextSetRGBStrokeColor(
    context: CFTypeRef,
    red: f64,
    green: f64,
    blue: f64,
    alpha: f64,
) {
    if let Some(state) = gstate(context) {
        state.stroke = Ink::Color([red, green, blue, alpha]);
    }
}

pub unsafe extern "C" fn CGContextSetGrayFillColor(context: CFTypeRef, gray: f64, alpha: f64) {
    unsafe { CGContextSetRGBFillColor(context, gray, gray, gray, alpha) };
}

pub unsafe extern "C" fn CGContextSetGrayStrokeColor(context: CFTypeRef, gray: f64, alpha: f64) {
    unsafe { CGContextSetRGBStrokeColor(context, gray, gray, gray, alpha) };
}

fn color_of<'a>(color: CFTypeRef) -> Option<&'a Color> {
    let class = objc::class::lookup(c"__CGColor").expect("installed during bootstrap");
    // SAFETY: null or an object a guest received from this runtime.
    if color.is_null() || !unsafe { corefoundation::base::is_kind_of(color, class) } {
        return None;
    }
    // SAFETY: a `__CGColor`, whose body is `Color`.
    Some(unsafe { &*(color as *const Color) })
}

pub unsafe extern "C" fn CGContextSetFillColorWithColor(context: CFTypeRef, color: CFTypeRef) {
    if let (Some(state), Some(color)) = (gstate(context), color_of(color)) {
        state.fill = Ink::Color(color.components);
    }
}

pub unsafe extern "C" fn CGContextSetStrokeColorWithColor(context: CFTypeRef, color: CFTypeRef) {
    if let (Some(state), Some(color)) = (gstate(context), color_of(color)) {
        state.stroke = Ink::Color(color.components);
    }
}

pub unsafe extern "C" fn CGContextSetFillColorSpace(context: CFTypeRef, space: CFTypeRef) {
    if let Some(state) = gstate(context) {
        state.fill_components = crate::graphics::space_components(space).unwrap_or(3);
        // A new space resets the colour to its initial one, opaque black.
        state.fill = Ink::Color([0.0, 0.0, 0.0, 1.0]);
    }
}

pub unsafe extern "C" fn CGContextSetStrokeColorSpace(context: CFTypeRef, space: CFTypeRef) {
    if let Some(state) = gstate(context) {
        state.stroke_components = crate::graphics::space_components(space).unwrap_or(3);
        state.stroke = Ink::Color([0.0, 0.0, 0.0, 1.0]);
    }
}

/// R, G, B, A from `components` read as the space's colour and an alpha.
///
/// # Safety
///
/// `components` holds `space_components + 1` values, or is null.
unsafe fn rgba_from(components: *const f64, space_components: usize) -> Option<[f64; 4]> {
    if components.is_null() {
        return None;
    }
    // SAFETY: the caller's count.
    let c = unsafe { std::slice::from_raw_parts(components, space_components + 1) };
    Some(match space_components {
        1 => [c[0], c[0], c[0], c[1]],
        _ => [c[0], c[1], c[2], c[3]],
    })
}

pub unsafe extern "C" fn CGContextSetFillColor(context: CFTypeRef, components: *const f64) {
    if let Some(state) = gstate(context)
        && state.fill_components != 0
        && let Some(rgba) = unsafe { rgba_from(components, state.fill_components) }
    {
        state.fill = Ink::Color(rgba);
    }
}

pub unsafe extern "C" fn CGContextSetStrokeColor(context: CFTypeRef, components: *const f64) {
    if let Some(state) = gstate(context)
        && state.stroke_components != 0
        && let Some(rgba) = unsafe { rgba_from(components, state.stroke_components) }
    {
        state.stroke = Ink::Color(rgba);
    }
}

/// The ink for a pattern set with `components`: for an uncoloured pattern
/// its colour, read as RGB and alpha because every base space here is RGB.
///
/// # Safety
///
/// `components` is null or holds four values.
unsafe fn pattern_ink(pattern: CFTypeRef, components: *const f64) -> Option<Ink> {
    let pattern = Retained::new(pattern)?;
    let color = match components.is_null() {
        true => [0.0, 0.0, 0.0, 1.0],
        // SAFETY: the caller's obligation.
        false => unsafe { rgba_from(components, 3) }.unwrap_or([0.0, 0.0, 0.0, 1.0]),
    };
    Some(Ink::Pattern(pattern, color))
}

pub unsafe extern "C" fn CGContextSetFillPattern(
    context: CFTypeRef,
    pattern: CFTypeRef,
    components: *const f64,
) {
    if let Some(state) = gstate(context)
        && let Some(ink) = unsafe { pattern_ink(pattern, components) }
    {
        state.fill = ink;
    }
}

pub unsafe extern "C" fn CGContextSetStrokePattern(
    context: CFTypeRef,
    pattern: CFTypeRef,
    components: *const f64,
) {
    if let Some(state) = gstate(context)
        && let Some(ink) = unsafe { pattern_ink(pattern, components) }
    {
        state.stroke = ink;
    }
}

pub unsafe extern "C" fn CGContextSetPatternPhase(context: CFTypeRef, phase: CGSize) {
    if let Some(state) = gstate(context) {
        state.pattern_phase = (phase.width, phase.height);
    }
}

pub unsafe extern "C" fn CGContextSetAlpha(context: CFTypeRef, alpha: f64) {
    if let Some(state) = gstate(context) {
        state.alpha = alpha.clamp(0.0, 1.0);
    }
}

//
// Line style and compositing
//

pub unsafe extern "C" fn CGContextSetLineWidth(context: CFTypeRef, width: f64) {
    if let Some(state) = gstate(context) {
        state.line.width = width.max(0.0);
    }
}

pub unsafe extern "C" fn CGContextSetLineCap(context: CFTypeRef, cap: i32) {
    if let Some(state) = gstate(context) {
        state.line.cap = match cap {
            1 => sk::LineCap::Round,
            2 => sk::LineCap::Square,
            _ => sk::LineCap::Butt,
        };
    }
}

pub unsafe extern "C" fn CGContextSetLineJoin(context: CFTypeRef, join: i32) {
    if let Some(state) = gstate(context) {
        state.line.join = match join {
            1 => sk::LineJoin::Round,
            2 => sk::LineJoin::Bevel,
            _ => sk::LineJoin::Miter,
        };
    }
}

pub unsafe extern "C" fn CGContextSetMiterLimit(context: CFTypeRef, limit: f64) {
    if let Some(state) = gstate(context) {
        state.line.miter = limit.max(0.0);
    }
}

pub unsafe extern "C" fn CGContextSetLineDash(
    context: CFTypeRef,
    phase: f64,
    lengths: *const f64,
    count: usize,
) {
    let Some(state) = gstate(context) else {
        return;
    };
    state.line.dash = match lengths.is_null() || count == 0 {
        true => None,
        // SAFETY: the caller supplies `count` lengths.
        false => Some((
            unsafe { std::slice::from_raw_parts(lengths, count) }.to_vec(),
            phase,
        )),
    };
}

/// Quartz's flatness is how far a curve may stray from its line segments;
/// the rasterizer here flattens to its own tolerance.
unsafe extern "C" fn CGContextSetFlatness(_context: CFTypeRef, _flatness: f64) {}

/// `CGBlendMode` as the rasterizer's.
fn blend_mode(mode: i32) -> sk::BlendMode {
    use sk::BlendMode as B;
    match mode {
        1 => B::Multiply,
        2 => B::Screen,
        3 => B::Overlay,
        4 => B::Darken,
        5 => B::Lighten,
        6 => B::ColorDodge,
        7 => B::ColorBurn,
        8 => B::SoftLight,
        9 => B::HardLight,
        10 => B::Difference,
        11 => B::Exclusion,
        12 => B::Hue,
        13 => B::Saturation,
        14 => B::Color,
        15 => B::Luminosity,
        16 => B::Clear,
        17 => B::Source,
        18 => B::SourceIn,
        19 => B::SourceOut,
        20 => B::SourceAtop,
        21 => B::DestinationOver,
        22 => B::DestinationIn,
        23 => B::DestinationOut,
        24 => B::DestinationAtop,
        25 => B::Xor,
        // FIXME (ACCURACY): `kCGBlendModePlusDarker` has no counterpart in
        // the rasterizer and draws as normal.
        27 => B::Plus,
        _ => B::SourceOver,
    }
}

pub unsafe extern "C" fn CGContextSetBlendMode(context: CFTypeRef, mode: i32) {
    if let Some(state) = gstate(context) {
        state.blend = blend_mode(mode);
    }
}

/// `CGContextSetCompositeOperation`, private: an `NSCompositingOperation`,
/// which is how AppKit and Cairo ask for the Porter-Duff operators.
pub unsafe extern "C" fn CGContextSetCompositeOperation(context: CFTypeRef, operation: i32) {
    use sk::BlendMode as B;
    let mode = match operation {
        0 => B::Clear,
        1 => B::Source,
        3 => B::SourceIn,
        4 => B::SourceOut,
        5 => B::SourceAtop,
        6 => B::DestinationOver,
        7 => B::DestinationIn,
        8 => B::DestinationOut,
        9 => B::DestinationAtop,
        10 => B::Xor,
        13 => B::Plus,
        // Source-over, highlight (which is source-over), and plus-darker,
        // which has no counterpart - see `blend_mode`.
        _ => B::SourceOver,
    };
    if let Some(state) = gstate(context) {
        state.blend = mode;
    }
}

pub unsafe extern "C" fn CGContextSetInterpolationQuality(context: CFTypeRef, quality: i32) {
    if let Some(state) = gstate(context) {
        // `kCGInterpolationNone` and `Low` sample; the rest filter.
        state.quality = match quality {
            1 | 2 => sk::FilterQuality::Nearest,
            _ => sk::FilterQuality::Bilinear,
        };
    }
}

pub unsafe extern "C" fn CGContextSetShouldAntialias(context: CFTypeRef, antialias: u8) {
    if let Some(state) = gstate(context) {
        state.antialias = antialias != 0;
    }
}

/// The font-rendering switches, none of which change what an outline fills
/// here: there is no subpixel positioning or LCD smoothing to turn off.
unsafe extern "C" fn ignored_flag(_context: CFTypeRef, _value: u8) {}

//
// The current path
//

fn path<'a>(context: CFTypeRef) -> Option<(&'a mut Elements, CGAffineTransform)> {
    let state = state_of(context)?;
    let ctm = state.current.ctm;
    Some((&mut state.path, ctm))
}

pub unsafe extern "C" fn CGContextBeginPath(context: CFTypeRef) {
    if let Some((path, _)) = path(context) {
        path.clear();
    }
}

pub unsafe extern "C" fn CGContextMoveToPoint(context: CFTypeRef, x: f64, y: f64) {
    if let Some((path, ctm)) = path(context) {
        path.move_to(ctm, x, y);
    }
}

pub unsafe extern "C" fn CGContextAddLineToPoint(context: CFTypeRef, x: f64, y: f64) {
    if let Some((path, ctm)) = path(context) {
        path.line_to(ctm, x, y);
    }
}

pub unsafe extern "C" fn CGContextAddQuadCurveToPoint(
    context: CFTypeRef,
    cx: f64,
    cy: f64,
    x: f64,
    y: f64,
) {
    if let Some((path, ctm)) = path(context) {
        path.quad_to(ctm, cx, cy, x, y);
    }
}

#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn CGContextAddCurveToPoint(
    context: CFTypeRef,
    c1x: f64,
    c1y: f64,
    c2x: f64,
    c2y: f64,
    x: f64,
    y: f64,
) {
    if let Some((path, ctm)) = path(context) {
        path.cubic_to(ctm, c1x, c1y, c2x, c2y, x, y);
    }
}

pub unsafe extern "C" fn CGContextClosePath(context: CFTypeRef) {
    if let Some((path, _)) = path(context) {
        path.close();
    }
}

pub unsafe extern "C" fn CGContextAddRect(context: CFTypeRef, rect: CGRect) {
    if let Some((path, ctm)) = path(context) {
        path.rect(ctm, rect);
    }
}

pub unsafe extern "C" fn CGContextAddRects(context: CFTypeRef, rects: *const CGRect, count: usize) {
    let Some((path, ctm)) = path(context) else {
        return;
    };
    if rects.is_null() {
        return;
    }
    // SAFETY: the caller supplies `count` rectangles.
    for rect in unsafe { std::slice::from_raw_parts(rects, count) } {
        path.rect(ctm, *rect);
    }
}

pub unsafe extern "C" fn CGContextAddEllipseInRect(context: CFTypeRef, rect: CGRect) {
    if let Some((path, ctm)) = path(context) {
        path.ellipse(ctm, rect);
    }
}

#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn CGContextAddArc(
    context: CFTypeRef,
    x: f64,
    y: f64,
    radius: f64,
    start: f64,
    end: f64,
    clockwise: i32,
) {
    if let Some((path, ctm)) = path(context) {
        path.arc(ctm, x, y, radius, start, end, clockwise != 0);
    }
}

pub unsafe extern "C" fn CGContextAddArcToPoint(
    context: CFTypeRef,
    x1: f64,
    y1: f64,
    x2: f64,
    y2: f64,
    radius: f64,
) {
    if let Some((path, ctm)) = path(context) {
        path.arc_to(ctm, x1, y1, x2, y2, radius);
    }
}

pub unsafe extern "C" fn CGContextAddLines(
    context: CFTypeRef,
    points: *const CGPoint,
    count: usize,
) {
    let Some((path, ctm)) = path(context) else {
        return;
    };
    if points.is_null() || count == 0 {
        return;
    }
    // SAFETY: the caller supplies `count` points.
    let points = unsafe { std::slice::from_raw_parts(points, count) };
    path.move_to(ctm, points[0].x, points[0].y);
    for p in &points[1..] {
        path.line_to(ctm, p.x, p.y);
    }
}

pub unsafe extern "C" fn CGContextAddPath(context: CFTypeRef, other: CFTypeRef) {
    let Some(source) = crate::cgpath::elements_of(other.cast()).map(|e| e.clone()) else {
        return;
    };
    if let Some((path, ctm)) = path(context) {
        path.append(ctm, &source);
    }
}

pub unsafe extern "C" fn CGContextIsPathEmpty(context: CFTypeRef) -> bool {
    path(context).is_none_or(|(path, _)| path.is_empty())
}

pub unsafe extern "C" fn CGContextGetPathCurrentPoint(context: CFTypeRef) -> CGPoint {
    let Some((path, ctm)) = path(context) else {
        return CGPoint::default();
    };
    match (path.current, ctm.inverse()) {
        (Some(p), Some(inverse)) => {
            let p = inverse.apply(p.x, p.y);
            CGPoint { x: p.x, y: p.y }
        }
        _ => CGPoint::default(),
    }
}

/// `CGContextGetPathBoundingBox`, in user space.
pub unsafe extern "C" fn CGContextGetPathBoundingBox(context: CFTypeRef) -> CGRect {
    let Some((path, ctm)) = path(context) else {
        return NULL_RECT;
    };
    let Some(inverse) = ctm.inverse() else {
        return NULL_RECT;
    };
    let mut user = Elements::default();
    user.append(inverse, path);
    user.bounds().unwrap_or(NULL_RECT)
}

pub unsafe extern "C" fn CGContextReplacePathWithStrokedPath(context: CFTypeRef) {
    let Some(current) = path(context).map(|(path, _)| path.clone()) else {
        return;
    };
    let outline = quartz::stroked_outline(context, &current).unwrap_or_default();
    if let Some((path, _)) = path(context) {
        *path = outline;
    }
}

/// The current path, taken: painting and clipping both consume it.
fn take_path(context: CFTypeRef) -> Option<Elements> {
    path(context).map(|(path, _)| std::mem::take(path))
}

//
// Painting
//

pub unsafe extern "C" fn CGContextFillPath(context: CFTypeRef) {
    if let Some(path) = take_path(context) {
        quartz::fill(context, &path, sk::FillRule::Winding, false);
    }
}

pub unsafe extern "C" fn CGContextEOFillPath(context: CFTypeRef) {
    if let Some(path) = take_path(context) {
        quartz::fill(context, &path, sk::FillRule::EvenOdd, false);
    }
}

pub unsafe extern "C" fn CGContextStrokePath(context: CFTypeRef) {
    if let Some(path) = take_path(context) {
        quartz::stroke(context, &path);
    }
}

/// `CGContextDrawPath(CGContextRef, CGPathDrawingMode)`
pub unsafe extern "C" fn CGContextDrawPath(context: CFTypeRef, mode: i32) {
    let Some(path) = take_path(context) else {
        return;
    };
    // `kCGPathFill`, `EOFill`, `Stroke`, `FillStroke`, `EOFillStroke`.
    match mode {
        0 | 3 => quartz::fill(context, &path, sk::FillRule::Winding, false),
        1 | 4 => quartz::fill(context, &path, sk::FillRule::EvenOdd, false),
        _ => {}
    }
    if matches!(mode, 2..=4) {
        quartz::stroke(context, &path);
    }
}

/// A one-off path through the CTM, for the calls that paint a shape without
/// touching the current path.
fn shape(
    context: CFTypeRef,
    build: impl FnOnce(&mut Elements, CGAffineTransform),
) -> Option<Elements> {
    let ctm = gstate(context)?.ctm;
    let mut shape = Elements::default();
    build(&mut shape, ctm);
    Some(shape)
}

pub unsafe extern "C" fn CGContextFillRect(context: CFTypeRef, rect: CGRect) {
    if let Some(shape) = shape(context, |e, m| e.rect(m, rect)) {
        quartz::fill(context, &shape, sk::FillRule::Winding, false);
    }
}

pub unsafe extern "C" fn CGContextFillRects(
    context: CFTypeRef,
    rects: *const CGRect,
    count: usize,
) {
    if rects.is_null() {
        return;
    }
    // SAFETY: the caller supplies `count` rectangles.
    let rects = unsafe { std::slice::from_raw_parts(rects, count) };
    if let Some(shape) = shape(context, |e, m| rects.iter().for_each(|r| e.rect(m, *r))) {
        quartz::fill(context, &shape, sk::FillRule::Winding, false);
    }
}

pub unsafe extern "C" fn CGContextStrokeRect(context: CFTypeRef, rect: CGRect) {
    if let Some(shape) = shape(context, |e, m| e.rect(m, rect)) {
        quartz::stroke(context, &shape);
    }
}

pub unsafe extern "C" fn CGContextStrokeRectWithWidth(
    context: CFTypeRef,
    rect: CGRect,
    width: f64,
) {
    let Some(state) = gstate(context) else {
        return;
    };
    let saved = state.line.width;
    state.line.width = width.max(0.0);
    unsafe { CGContextStrokeRect(context, rect) };
    if let Some(state) = gstate(context) {
        state.line.width = saved;
    }
}

pub unsafe extern "C" fn CGContextFillEllipseInRect(context: CFTypeRef, rect: CGRect) {
    if let Some(shape) = shape(context, |e, m| e.ellipse(m, rect)) {
        quartz::fill(context, &shape, sk::FillRule::Winding, false);
    }
}

pub unsafe extern "C" fn CGContextStrokeEllipseInRect(context: CFTypeRef, rect: CGRect) {
    if let Some(shape) = shape(context, |e, m| e.ellipse(m, rect)) {
        quartz::stroke(context, &shape);
    }
}

/// `CGContextStrokeLineSegments(CGContextRef, const CGPoint *, size_t)`: each
/// pair of points is a line of its own.
pub unsafe extern "C" fn CGContextStrokeLineSegments(
    context: CFTypeRef,
    points: *const CGPoint,
    count: usize,
) {
    if points.is_null() {
        return;
    }
    // SAFETY: the caller supplies `count` points.
    let points = unsafe { std::slice::from_raw_parts(points, count) };
    if let Some(shape) = shape(context, |e, m| {
        for pair in points.chunks_exact(2) {
            e.move_to(m, pair[0].x, pair[0].y);
            e.line_to(m, pair[1].x, pair[1].y);
        }
    }) {
        quartz::stroke(context, &shape);
    }
}

pub unsafe extern "C" fn CGContextClearRect(context: CFTypeRef, rect: CGRect) {
    quartz::clear(context, rect);
}

//
// Clipping
//

pub unsafe extern "C" fn CGContextClip(context: CFTypeRef) {
    if let Some(path) = take_path(context) {
        quartz::clip(context, &path, sk::FillRule::Winding);
    }
}

pub unsafe extern "C" fn CGContextEOClip(context: CFTypeRef) {
    if let Some(path) = take_path(context) {
        quartz::clip(context, &path, sk::FillRule::EvenOdd);
    }
}

pub unsafe extern "C" fn CGContextClipToRect(context: CFTypeRef, rect: CGRect) {
    if let Some(shape) = shape(context, |e, m| e.rect(m, rect)) {
        quartz::clip(context, &shape, sk::FillRule::Winding);
    }
}

pub unsafe extern "C" fn CGContextClipToRects(
    context: CFTypeRef,
    rects: *const CGRect,
    count: usize,
) {
    if rects.is_null() {
        return;
    }
    // SAFETY: the caller supplies `count` rectangles.
    let rects = unsafe { std::slice::from_raw_parts(rects, count) };
    if let Some(shape) = shape(context, |e, m| rects.iter().for_each(|r| e.rect(m, *r))) {
        quartz::clip(context, &shape, sk::FillRule::Winding);
    }
}

pub unsafe extern "C" fn CGContextClipToMask(context: CFTypeRef, rect: CGRect, mask: CFTypeRef) {
    quartz::clip_to_mask(context, rect, mask);
}

/// `CGContextGetClipBoundingBox`, in user space: the device rectangle the clip
/// leaves, carried back through the CTM.
pub unsafe extern "C" fn CGContextGetClipBoundingBox(context: CFTypeRef) -> CGRect {
    let (Some([left, top, right, bottom]), Some(frame), Some(state)) = (
        quartz::clip_device_bounds(context),
        quartz::frame_of(context),
        gstate(context),
    ) else {
        return NULL_RECT;
    };
    if right <= left || bottom <= top {
        return NULL_RECT;
    }
    let Some(device_to_user) = state.ctm.then(frame.base).inverse() else {
        return NULL_RECT;
    };
    let rect = CGRect {
        origin: CGPoint { x: left, y: top },
        size: CGSize {
            width: right - left,
            height: bottom - top,
        },
    };
    unsafe { CGRectApplyAffineTransform(rect, device_to_user) }
}

//
// Images and shadings
//

pub unsafe extern "C" fn CGContextDrawImage(context: CFTypeRef, rect: CGRect, image: CFTypeRef) {
    if crate::graphics::is_image_mask(image) {
        if let Some((width, height, coverage)) = crate::graphics::image_coverage(image) {
            quartz::draw_through_mask(context, rect, width, height, coverage);
        }
        return;
    }
    if let Some((width, height, pixels)) = crate::graphics::image_bgra(image) {
        quartz::draw_pixels(context, rect, width, height, pixels);
    }
}

pub unsafe extern "C" fn CGContextDrawShading(context: CFTypeRef, shading: CFTypeRef) {
    if let Some(paint) = crate::cgpaint::shading_paint(shading) {
        quartz::draw_shading(context, paint);
    }
}

//
// Pages and flushing
//

/// Every context here draws immediately, so there is nothing to flush.
unsafe extern "C" fn ignored_context(_context: CFTypeRef) {}

/// `CGContextBeginPage(CGContextRef, const CGRect *)`: a bitmap context has
/// one page and nothing here makes a PDF context.
unsafe extern "C" fn CGContextBeginPage(_context: CFTypeRef, _media: *const CGRect) {}

/// `CGContextRef CGPDFContextCreateWithURL(CFURLRef, const CGRect *,
/// CFDictionaryRef)`: NULL - there is no PDF writer, and a program printing to
/// a file gets the failure it already handles.
unsafe extern "C" fn CGPDFContextCreateWithURL(
    _url: CFTypeRef,
    _media: *const CGRect,
    _info: CFTypeRef,
) -> CFTypeRef {
    std::ptr::null()
}

pub unsafe extern "C" fn CGRectApplyAffineTransform(rect: CGRect, t: CGAffineTransform) -> CGRect {
    let (x0, y0) = (rect.origin.x, rect.origin.y);
    let (x1, y1) = (x0 + rect.size.width, y0 + rect.size.height);
    let corners = [
        t.apply(x0, y0),
        t.apply(x1, y0),
        t.apply(x0, y1),
        t.apply(x1, y1),
    ];
    let [left, bottom, right, top] = corners.iter().fold(
        [f64::MAX, f64::MAX, f64::MIN, f64::MIN],
        |[l, b, r, t], p| [l.min(p.x), b.min(p.y), r.max(p.x), t.max(p.y)],
    );
    CGRect {
        origin: CGPoint { x: left, y: bottom },
        size: CGSize {
            width: right - left,
            height: top - bottom,
        },
    }
}

//
// Colours
//

fn new_color(components: [f64; 4]) -> CFTypeRef {
    let class = objc::class::lookup(c"__CGColor").expect("installed during bootstrap");
    // SAFETY: `Color` is the registered class layout.
    let color = unsafe { corefoundation::base::allocate::<Color>(class) };
    // SAFETY: a fresh allocation.
    unsafe { (*color).components = components };
    color as CFTypeRef
}

/// `CGColorCreate`, reading the components as gray and alpha or as R, G, B
/// and alpha by how many the color space has. A space this runtime did not
/// make is taken as RGB.
pub unsafe extern "C" fn CGColorCreate(space: CFTypeRef, components: *const f64) -> CFTypeRef {
    let count = crate::graphics::space_components(space).unwrap_or(3).max(1);
    // SAFETY: the space's components and an alpha.
    match unsafe { rgba_from(components, count) } {
        Some(rgba) => new_color(rgba),
        None => std::ptr::null(),
    }
}

pub unsafe extern "C" fn CGColorCreateGenericRGB(r: f64, g: f64, b: f64, a: f64) -> CFTypeRef {
    new_color([r, g, b, a])
}

pub unsafe extern "C" fn CGColorCreateGenericGray(gray: f64, alpha: f64) -> CFTypeRef {
    new_color([gray, gray, gray, alpha])
}

pub unsafe extern "C" fn CGColorRelease(color: CFTypeRef) {
    if !color.is_null() {
        unsafe { corefoundation::api::CFRelease(color) };
    }
}

pub unsafe extern "C" fn CGColorGetComponents(color: CFTypeRef) -> *const f64 {
    color_of(color).map_or(std::ptr::null(), |color| color.components.as_ptr())
}

pub unsafe extern "C" fn CGColorGetNumberOfComponents(color: CFTypeRef) -> usize {
    color_of(color).map_or(0, |_| 4)
}

pub unsafe extern "C" fn CGColorGetAlpha(color: CFTypeRef) -> f64 {
    color_of(color).map_or(0.0, |color| color.components[3])
}

/// `kCGColorBlack`, `kCGColorWhite` and `kCGColorClear` by name, for the
/// `CFStringRef` constants [`data_symbols`] publishes.
pub unsafe extern "C" fn CGColorGetConstantColor(name: CFTypeRef) -> CFTypeRef {
    static COLORS: std::sync::OnceLock<[usize; 3]> = std::sync::OnceLock::new();
    let colors = COLORS.get_or_init(|| {
        [
            new_color([0.0, 0.0, 0.0, 1.0]) as usize,
            new_color([1.0, 1.0, 1.0, 1.0]) as usize,
            new_color([0.0, 0.0, 0.0, 0.0]) as usize,
        ]
    });
    for (at, key) in ["kCGColorBlack", "kCGColorWhite", "kCGColorClear"]
        .into_iter()
        .enumerate()
    {
        let key = corefoundation::base::interned_name(key) as CFTypeRef;
        // SAFETY: both are strings.
        if !name.is_null() && unsafe { corefoundation::api::CFEqual(name, key) } != 0 {
            return colors[at] as CFTypeRef;
        }
    }
    std::ptr::null()
}

pub unsafe extern "C" fn CGColorGetTypeID() -> corefoundation::base::CFTypeID {
    corefoundation::base::type_id_of(
        objc::class::lookup(c"__CGColor").expect("installed during bootstrap"),
    )
}

/// Every colour here is kept as RGBA, so its space is device RGB.
pub unsafe extern "C" fn CGColorGetColorSpace(color: CFTypeRef) -> CFTypeRef {
    static SPACE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    if color_of(color).is_none() {
        return std::ptr::null();
    }
    // SAFETY: a fresh space, kept for the process as Apple's shared ones are.
    *SPACE.get_or_init(|| unsafe { crate::graphics::CGColorSpaceCreateDeviceRGB() } as usize)
        as CFTypeRef
}

/// The model of a space: `kCGColorSpaceModelMonochrome`, `RGB` or `Pattern`.
pub unsafe extern "C" fn CGColorSpaceGetModel(space: CFTypeRef) -> i32 {
    match crate::graphics::space_components(space) {
        Some(1) => 0,
        Some(0) => 6,
        Some(_) => 1,
        None => -1,
    }
}

/// `CGRectNull`.
const NULL_RECT: CGRect = CGRect {
    origin: CGPoint {
        x: f64::INFINITY,
        y: f64::INFINITY,
    },
    size: CGSize {
        width: 0.0,
        height: 0.0,
    },
};

exports::exports! {
    functions {
        "CGBitmapContextCreate" => CGBitmapContextCreate,
        "CGBitmapContextGetData" => CGBitmapContextGetData,
        "CGBitmapContextGetWidth" => CGBitmapContextGetWidth,
        "CGBitmapContextGetHeight" => CGBitmapContextGetHeight,
        "CGBitmapContextCreateImage" => CGBitmapContextCreateImage,
        "CGBitmapContextGetBitmapInfo" => CGBitmapContextGetBitmapInfo,
        "CGBitmapContextGetBitsPerComponent" => CGBitmapContextGetBitsPerComponent,
        "CGBitmapContextGetBitsPerPixel" => CGBitmapContextGetBitsPerPixel,
        "CGBitmapContextGetBytesPerRow" => CGBitmapContextGetBytesPerRow,
        "CGBitmapContextGetColorSpace" => CGBitmapContextGetColorSpace,
        "CGContextRetain" => CGContextRetain,
        "CGContextRelease" => CGContextRelease,
        "CGContextSaveGState" => CGContextSaveGState,
        "CGContextRestoreGState" => CGContextRestoreGState,
        "CGContextConcatCTM" => CGContextConcatCTM,
        "CGContextGetCTM" => CGContextGetCTM,
        "CGContextSetCTM" => CGContextSetCTM,
        "CGContextTranslateCTM" => CGContextTranslateCTM,
        "CGContextScaleCTM" => CGContextScaleCTM,
        "CGContextRotateCTM" => CGContextRotateCTM,
        "CGContextSetRGBFillColor" => CGContextSetRGBFillColor,
        "CGContextSetRGBStrokeColor" => CGContextSetRGBStrokeColor,
        "CGContextSetGrayFillColor" => CGContextSetGrayFillColor,
        "CGContextSetGrayStrokeColor" => CGContextSetGrayStrokeColor,
        "CGContextSetFillColorWithColor" => CGContextSetFillColorWithColor,
        "CGContextSetStrokeColorWithColor" => CGContextSetStrokeColorWithColor,
        "CGContextSetFillColorSpace" => CGContextSetFillColorSpace,
        "CGContextSetStrokeColorSpace" => CGContextSetStrokeColorSpace,
        "CGContextSetFillColor" => CGContextSetFillColor,
        "CGContextSetStrokeColor" => CGContextSetStrokeColor,
        "CGContextSetFillPattern" => CGContextSetFillPattern,
        "CGContextSetStrokePattern" => CGContextSetStrokePattern,
        "CGContextSetPatternPhase" => CGContextSetPatternPhase,
        "CGContextSetAlpha" => CGContextSetAlpha,
        "CGContextSetLineWidth" => CGContextSetLineWidth,
        "CGContextSetLineCap" => CGContextSetLineCap,
        "CGContextSetLineJoin" => CGContextSetLineJoin,
        "CGContextSetMiterLimit" => CGContextSetMiterLimit,
        "CGContextSetLineDash" => CGContextSetLineDash,
        "CGContextSetFlatness" => CGContextSetFlatness,
        "CGContextSetBlendMode" => CGContextSetBlendMode,
        "CGContextSetCompositeOperation" => CGContextSetCompositeOperation,
        "CGContextSetInterpolationQuality" => CGContextSetInterpolationQuality,
        "CGContextSetShouldAntialias" => CGContextSetShouldAntialias,
        "CGContextSetAllowsAntialiasing" | "CGContextSetShouldSmoothFonts" | "CGContextSetAllowsFontSmoothing" | "CGContextSetShouldSubpixelPositionFonts" | "CGContextSetAllowsFontSubpixelPositioning" | "CGContextSetShouldSubpixelQuantizeFonts" | "CGContextSetAllowsFontSubpixelQuantization" => ignored_flag,
        "CGContextBeginPath" => CGContextBeginPath,
        "CGContextMoveToPoint" => CGContextMoveToPoint,
        "CGContextAddLineToPoint" => CGContextAddLineToPoint,
        "CGContextAddQuadCurveToPoint" => CGContextAddQuadCurveToPoint,
        "CGContextAddCurveToPoint" => CGContextAddCurveToPoint,
        "CGContextClosePath" => CGContextClosePath,
        "CGContextAddRect" => CGContextAddRect,
        "CGContextAddRects" => CGContextAddRects,
        "CGContextAddEllipseInRect" => CGContextAddEllipseInRect,
        "CGContextAddArc" => CGContextAddArc,
        "CGContextAddArcToPoint" => CGContextAddArcToPoint,
        "CGContextAddLines" => CGContextAddLines,
        "CGContextAddPath" => CGContextAddPath,
        "CGContextIsPathEmpty" => CGContextIsPathEmpty,
        "CGContextGetPathCurrentPoint" => CGContextGetPathCurrentPoint,
        "CGContextGetPathBoundingBox" => CGContextGetPathBoundingBox,
        "CGContextReplacePathWithStrokedPath" => CGContextReplacePathWithStrokedPath,
        "CGContextFillPath" => CGContextFillPath,
        "CGContextEOFillPath" => CGContextEOFillPath,
        "CGContextStrokePath" => CGContextStrokePath,
        "CGContextDrawPath" => CGContextDrawPath,
        "CGContextFillRect" => CGContextFillRect,
        "CGContextFillRects" => CGContextFillRects,
        "CGContextStrokeRect" => CGContextStrokeRect,
        "CGContextStrokeRectWithWidth" => CGContextStrokeRectWithWidth,
        "CGContextFillEllipseInRect" => CGContextFillEllipseInRect,
        "CGContextStrokeEllipseInRect" => CGContextStrokeEllipseInRect,
        "CGContextStrokeLineSegments" => CGContextStrokeLineSegments,
        "CGContextClearRect" => CGContextClearRect,
        "CGContextClip" => CGContextClip,
        "CGContextEOClip" => CGContextEOClip,
        "CGContextClipToRect" => CGContextClipToRect,
        "CGContextClipToRects" => CGContextClipToRects,
        "CGContextClipToMask" => CGContextClipToMask,
        "CGContextGetClipBoundingBox" => CGContextGetClipBoundingBox,
        "CGContextDrawImage" => CGContextDrawImage,
        "CGContextDrawShading" => CGContextDrawShading,
        "CGContextFlush" | "CGContextSynchronize" | "CGContextEndPage" => ignored_context,
        "CGContextBeginPage" => CGContextBeginPage,
        "CGPDFContextCreateWithURL" => CGPDFContextCreateWithURL,
        "CGRectApplyAffineTransform" => CGRectApplyAffineTransform,
        "CGColorCreate" => CGColorCreate,
        "CGColorCreateGenericRGB" => CGColorCreateGenericRGB,
        "CGColorCreateGenericGray" => CGColorCreateGenericGray,
        "CGColorRelease" => CGColorRelease,
        "CGColorGetComponents" => CGColorGetComponents,
        "CGColorGetNumberOfComponents" => CGColorGetNumberOfComponents,
        "CGColorGetAlpha" => CGColorGetAlpha,
        "CGColorGetConstantColor" => CGColorGetConstantColor,
        "CGColorGetTypeID" => CGColorGetTypeID,
        "CGColorGetColorSpace" => CGColorGetColorSpace,
        "CGColorSpaceGetModel" => CGColorSpaceGetModel,
    }
}

/// The `CFStringRef` color names `CGColorGetConstantColor` takes.
pub fn data_symbols() -> Vec<(String, u64)> {
    ["kCGColorBlack", "kCGColorWhite", "kCGColorClear"]
        .into_iter()
        .map(|name| {
            let symbol = format!("_{name}");
            let value = corefoundation::base::interned_name(name) as usize as u64;
            let cell = corefoundation::base::global_cell(&symbol, value);
            (symbol, cell)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x: f64, y: f64, width: f64, height: f64) -> CGRect {
        CGRect {
            origin: CGPoint { x, y },
            size: CGSize { width, height },
        }
    }

    #[test]
    fn draws_an_image_through_a_vertical_context_flip() {
        crate::bootstrap();
        let image = crate::graphics::image_from_bitmap(crate::raster::Bitmap {
            width: 1,
            height: 2,
            pixels: vec![255, 0, 0, 255, 0, 255, 0, 255],
        });
        let mut pixels = [0u8; 8];
        // SAFETY: `pixels` holds two writable RGBA rows and `image` is live.
        unsafe {
            let context =
                CGBitmapContextCreate(pixels.as_mut_ptr().cast(), 1, 2, 8, 4, std::ptr::null(), 3);
            CGContextTranslateCTM(context, 0.0, 2.0);
            CGContextScaleCTM(context, 1.0, -1.0);
            CGContextDrawImage(context, rect(0.0, 0.0, 1.0, 2.0), image);
            CGContextRelease(context);
            crate::graphics::CGImageRelease(image);
        }
        assert_eq!(pixels, [0, 255, 0, 255, 255, 0, 0, 255]);
    }

    #[test]
    fn fills_a_translated_rect_in_a_little_endian_bitmap() {
        crate::bootstrap();
        let mut pixels = [0u32; 4];
        // SAFETY: `pixels` is two writable rows of two pixels.
        unsafe {
            let context = CGBitmapContextCreate(
                pixels.as_mut_ptr().cast(),
                2,
                2,
                8,
                8,
                std::ptr::null(),
                0x2006,
            );
            CGContextSetRGBFillColor(context, 1.0, 0.0, 0.0, 1.0);
            CGContextTranslateCTM(context, 1.0, 1.0);
            CGContextFillRect(context, rect(0.0, 0.0, 1.0, 1.0));
            CGContextRelease(context);
        }
        // Device (1, 1) is the top row's second pixel, 0xAARRGGBB with the
        // skipped byte opaque as Qt's RGB32 images need it.
        assert_eq!(pixels, [0, 0xffff_0000, 0, 0]);
    }

    /// A little-endian context whose rows are padded is drawn on a copy, and
    /// its colours still land in the right bytes.
    #[test]
    fn fills_a_padded_little_endian_bitmap_in_its_own_order() {
        crate::bootstrap();
        // One pixel per row, padded to two.
        let mut pixels = [0u32; 4];
        // SAFETY: `pixels` is two writable rows of eight bytes.
        unsafe {
            let context = CGBitmapContextCreate(
                pixels.as_mut_ptr().cast(),
                1,
                2,
                8,
                8,
                std::ptr::null(),
                0x2002,
            );
            CGContextSetRGBFillColor(context, 1.0, 0.0, 0.0, 1.0);
            CGContextFillRect(context, rect(0.0, 0.0, 1.0, 2.0));
            CGContextRelease(context);
        }
        assert_eq!(pixels, [0xffff_0000, 0, 0xffff_0000, 0]);
    }

    #[test]
    fn saved_state_restores_the_transform() {
        crate::bootstrap();
        // SAFETY: a context over its own storage.
        unsafe {
            let context =
                CGBitmapContextCreate(std::ptr::null_mut(), 4, 4, 8, 16, std::ptr::null(), 1);
            CGContextSaveGState(context);
            CGContextScaleCTM(context, 2.0, 3.0);
            assert_eq!(CGContextGetCTM(context).d, 3.0);
            CGContextRestoreGState(context);
            assert_eq!(CGContextGetCTM(context), CGAffineTransformIdentity);
            let inverse = crate::CGAffineTransformInvert(CGAffineTransformMakeScale(2.0, 4.0));
            assert_eq!(inverse.a, 0.5);
            assert_eq!(inverse.d, 0.25);
            CGContextRelease(context);
        }
    }

    /// The four pixels of a 2x2 premultiplied RGBA context, top row first.
    fn pixels_after(draw: impl FnOnce(CFTypeRef)) -> [[u8; 4]; 4] {
        crate::bootstrap();
        let mut pixels = [[0u8; 4]; 4];
        // SAFETY: two writable rows of two RGBA pixels.
        unsafe {
            let context =
                CGBitmapContextCreate(pixels.as_mut_ptr().cast(), 2, 2, 8, 8, std::ptr::null(), 1);
            draw(context);
            CGContextRelease(context);
        }
        pixels
    }

    /// A path filled through the current path, which a fill consumes.
    #[test]
    fn a_filled_path_covers_its_pixels_and_is_consumed() {
        let pixels = pixels_after(|context| unsafe {
            CGContextSetRGBFillColor(context, 0.0, 0.0, 1.0, 1.0);
            CGContextMoveToPoint(context, 0.0, 0.0);
            CGContextAddLineToPoint(context, 2.0, 0.0);
            CGContextAddLineToPoint(context, 2.0, 1.0);
            CGContextAddLineToPoint(context, 0.0, 1.0);
            CGContextClosePath(context);
            CGContextFillPath(context);
            assert!(CGContextIsPathEmpty(context));
        });
        // The bottom row in user space is the second row in memory.
        assert_eq!(pixels, [[0; 4], [0; 4], [0, 0, 255, 255], [0, 0, 255, 255]]);
    }

    /// A clipped fill in a mode that ignores the source, or replaces the
    /// destination, still leaves everything outside the clip alone.
    #[test]
    fn a_clip_bounds_clear_and_copy_fills() {
        for (mode, inside) in [(16, [0u8; 4]), (17, [0, 0, 255, 255])] {
            let pixels = pixels_after(|context| unsafe {
                CGContextSetRGBFillColor(context, 1.0, 1.0, 1.0, 1.0);
                CGContextFillRect(context, rect(0.0, 0.0, 2.0, 2.0));
                CGContextClipToRect(context, rect(1.0, 0.0, 1.0, 2.0));
                CGContextSetBlendMode(context, mode);
                CGContextSetRGBFillColor(context, 0.0, 0.0, 1.0, 1.0);
                CGContextFillRect(context, rect(0.0, 0.0, 2.0, 2.0));
            });
            let white = [255u8; 4];
            assert_eq!(pixels, [white, inside, white, inside], "blend mode {mode}");
        }
    }

    /// A clip keeps drawing inside it, and restoring the state lifts it.
    #[test]
    fn a_clip_bounds_a_fill_until_restored() {
        let pixels = pixels_after(|context| unsafe {
            CGContextSaveGState(context);
            CGContextClipToRect(context, rect(1.0, 0.0, 1.0, 2.0));
            CGContextSetRGBFillColor(context, 1.0, 1.0, 1.0, 1.0);
            CGContextFillRect(context, rect(0.0, 0.0, 2.0, 2.0));
            assert_eq!(
                CGContextGetClipBoundingBox(context),
                rect(1.0, 0.0, 1.0, 2.0)
            );
            CGContextRestoreGState(context);
            CGContextSetRGBFillColor(context, 1.0, 0.0, 0.0, 1.0);
            CGContextFillRect(context, rect(0.0, 1.0, 1.0, 1.0));
        });
        assert_eq!(pixels, [[255, 0, 0, 255], [255; 4], [0; 4], [255; 4]]);
    }

    /// A line one unit wide, under a CTM that doubles it, covers a pixel either
    /// side of its centre.
    #[test]
    fn a_stroke_scales_its_width_with_the_ctm() {
        let pixels = pixels_after(|context| unsafe {
            CGContextScaleCTM(context, 2.0, 2.0);
            CGContextSetLineWidth(context, 1.0);
            CGContextSetRGBStrokeColor(context, 0.0, 1.0, 0.0, 1.0);
            CGContextMoveToPoint(context, 0.5, 0.0);
            CGContextAddLineToPoint(context, 0.5, 1.0);
            CGContextStrokePath(context);
        });
        assert_eq!(pixels, [[0, 255, 0, 255]; 4]);
    }

    /// Clearing leaves transparent black, whatever was under it.
    #[test]
    fn clear_rect_makes_pixels_transparent() {
        let pixels = pixels_after(|context| unsafe {
            CGContextSetRGBFillColor(context, 1.0, 1.0, 1.0, 1.0);
            CGContextFillRect(context, rect(0.0, 0.0, 2.0, 2.0));
            CGContextClearRect(context, rect(0.0, 0.0, 1.0, 2.0));
        });
        assert_eq!(pixels, [[0; 4], [255; 4], [0; 4], [255; 4]]);
    }

    /// A layer drawn back at its own size reproduces what was drawn into it.
    #[test]
    fn a_layer_draws_back_what_it_holds() {
        let pixels = pixels_after(|context| unsafe {
            let layer = crate::cgpaint::CGLayerCreateWithContext(
                context,
                CGSize {
                    width: 2.0,
                    height: 2.0,
                },
                std::ptr::null(),
            );
            let inner = crate::cgpaint::CGLayerGetContext(layer);
            CGContextSetRGBFillColor(inner, 0.0, 0.0, 1.0, 1.0);
            CGContextFillRect(inner, rect(0.0, 1.0, 2.0, 1.0));
            crate::cgpaint::CGContextDrawLayerAtPoint(context, CGPoint::default(), layer);
            crate::cgpaint::CGLayerRelease(layer);
        });
        assert_eq!(pixels, [[0, 0, 255, 255], [0, 0, 255, 255], [0; 4], [0; 4]]);
    }
}
