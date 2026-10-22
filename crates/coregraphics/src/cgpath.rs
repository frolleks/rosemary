//! `CGPath` and the path-building geometry a `CGContext`'s current path shares.
//!
//! A path is its elements, in the coordinates they were added in after the
//! transform passed with each. A context keeps its current path the same way,
//! with the CTM as that transform, which is when Quartz applies it.

#![allow(non_snake_case)]

use std::ffi::c_void;

use crate::{
    CGAffineTransform, CGAffineTransformIdentity, CGMutablePathRef, CGPath, CGPathElement,
    CGPathElementType, CGPathRef, CGPoint, CGRect, CGSize,
};

pub type Point = (f64, f64);

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Element {
    Move(Point),
    Line(Point),
    Quad(Point, Point),
    Cubic(Point, Point, Point),
    Close,
}

/// A sequence of elements, with the point the next element starts from.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Elements {
    pub list: Vec<Element>,
    /// The current point, if there is one.
    pub current: Option<Point>,
    /// Where the current subpath began, which a close returns to.
    start: Option<Point>,
}

/// `4/3 * (sqrt(2) - 1)`: the control distance that makes a cubic a quarter
/// circle to within 0.03%.
const KAPPA: f64 = 0.552_284_749_830_793_4;

impl Elements {
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    pub fn clear(&mut self) {
        *self = Elements::default();
    }

    pub fn move_to(&mut self, m: CGAffineTransform, x: f64, y: f64) {
        let p = m.apply(x, y);
        self.list.push(Element::Move(p));
        self.current = Some(p);
        self.start = Some(p);
    }

    /// A line, or a move when there is nowhere to draw from - which is what
    /// Quartz does rather than refuse.
    pub fn line_to(&mut self, m: CGAffineTransform, x: f64, y: f64) {
        if self.current.is_none() {
            return self.move_to(m, x, y);
        }
        let p = m.apply(x, y);
        self.list.push(Element::Line(p));
        self.current = Some(p);
    }

    pub fn quad_to(&mut self, m: CGAffineTransform, cx: f64, cy: f64, x: f64, y: f64) {
        if self.current.is_none() {
            self.move_to(m, cx, cy);
        }
        let p = m.apply(x, y);
        self.list.push(Element::Quad(m.apply(cx, cy), p));
        self.current = Some(p);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cubic_to(
        &mut self,
        m: CGAffineTransform,
        c1x: f64,
        c1y: f64,
        c2x: f64,
        c2y: f64,
        x: f64,
        y: f64,
    ) {
        if self.current.is_none() {
            self.move_to(m, c1x, c1y);
        }
        let p = m.apply(x, y);
        self.list
            .push(Element::Cubic(m.apply(c1x, c1y), m.apply(c2x, c2y), p));
        self.current = Some(p);
    }

    pub fn close(&mut self) {
        if self.current.is_none() || matches!(self.list.last(), Some(Element::Close) | None) {
            return;
        }
        self.list.push(Element::Close);
        self.current = self.start;
    }

    pub fn rect(&mut self, m: CGAffineTransform, r: CGRect) {
        let (x0, y0) = (r.origin.x, r.origin.y);
        let (x1, y1) = (x0 + r.size.width, y0 + r.size.height);
        self.move_to(m, x0, y0);
        self.line_to(m, x1, y0);
        self.line_to(m, x1, y1);
        self.line_to(m, x0, y1);
        self.close();
    }

    /// `CGPathAddRoundedRect`: a rectangle with elliptical corners, each
    /// radius clamped to half the side it sits on.
    pub fn rounded_rect(
        &mut self,
        m: CGAffineTransform,
        r: CGRect,
        corner_width: f64,
        corner_height: f64,
    ) {
        let (x0, y0) = (r.origin.x, r.origin.y);
        let (x1, y1) = (x0 + r.size.width, y0 + r.size.height);
        let rx = corner_width.clamp(0.0, r.size.width.abs() / 2.0);
        let ry = corner_height.clamp(0.0, r.size.height.abs() / 2.0);
        let (kx, ky) = (rx * KAPPA, ry * KAPPA);
        self.move_to(m, x0 + rx, y0);
        self.line_to(m, x1 - rx, y0);
        self.cubic_to(m, x1 - rx + kx, y0, x1, y0 + ry - ky, x1, y0 + ry);
        self.line_to(m, x1, y1 - ry);
        self.cubic_to(m, x1, y1 - ry + ky, x1 - rx + kx, y1, x1 - rx, y1);
        self.line_to(m, x0 + rx, y1);
        self.cubic_to(m, x0 + rx - kx, y1, x0, y1 - ry + ky, x0, y1 - ry);
        self.line_to(m, x0, y0 + ry);
        self.cubic_to(m, x0, y0 + ry - ky, x0 + rx - kx, y0, x0 + rx, y0);
        self.close();
    }

    /// The rectangle this path is, if it is exactly one: a move, three lines
    /// and a close (or four lines, the last returning to the start), with
    /// every side axis-aligned.
    pub fn as_rect(&self) -> Option<CGRect> {
        let (a, c) = match self.list.as_slice() {
            [
                Element::Move(a),
                Element::Line(_),
                Element::Line(c),
                Element::Line(_),
                Element::Close,
            ] => (a, c),
            [
                Element::Move(a),
                Element::Line(_),
                Element::Line(c),
                Element::Line(_),
                Element::Line(e),
                Element::Close,
            ] if e == a => (a, c),
            _ => return None,
        };
        let axis = |p: Point, q: Point| p.0 == q.0 || p.1 == q.1;
        let points = self.list.iter().filter_map(|e| match *e {
            Element::Move(p) | Element::Line(p) => Some(p),
            _ => None,
        });
        let points: Vec<Point> = points.collect();
        if !points.windows(2).all(|w| axis(w[0], w[1])) {
            return None;
        }
        let (l, r) = (a.0.min(c.0), a.0.max(c.0));
        let (b, t) = (a.1.min(c.1), a.1.max(c.1));
        Some(CGRect {
            origin: CGPoint { x: l, y: b },
            size: CGSize {
                width: r - l,
                height: t - b,
            },
        })
    }

    pub fn ellipse(&mut self, m: CGAffineTransform, r: CGRect) {
        let (cx, cy) = (
            r.origin.x + r.size.width / 2.0,
            r.origin.y + r.size.height / 2.0,
        );
        let (rx, ry) = (r.size.width / 2.0, r.size.height / 2.0);
        let (kx, ky) = (rx * KAPPA, ry * KAPPA);
        self.move_to(m, cx + rx, cy);
        self.cubic_to(m, cx + rx, cy + ky, cx + kx, cy + ry, cx, cy + ry);
        self.cubic_to(m, cx - kx, cy + ry, cx - rx, cy + ky, cx - rx, cy);
        self.cubic_to(m, cx - rx, cy - ky, cx - kx, cy - ry, cx, cy - ry);
        self.cubic_to(m, cx + kx, cy - ry, cx + rx, cy - ky, cx + rx, cy);
        self.close();
    }

    /// `CGPathAddArc`: a line to the arc's start when there is a current point,
    /// then the arc, in at most quarter turns.
    ///
    /// `clockwise` is in Quartz's y-up sense: the angle decreases.
    #[allow(clippy::too_many_arguments)]
    pub fn arc(
        &mut self,
        m: CGAffineTransform,
        x: f64,
        y: f64,
        radius: f64,
        start: f64,
        end: f64,
        clockwise: bool,
    ) {
        use std::f64::consts::TAU;
        let mut sweep = end - start;
        match clockwise {
            true => {
                if sweep > 0.0 {
                    sweep -= TAU * ((sweep / TAU).floor() + 1.0);
                }
                sweep = sweep.max(-TAU);
            }
            false => {
                if sweep < 0.0 {
                    sweep += TAU * ((-sweep / TAU).floor() + 1.0);
                }
                sweep = sweep.min(TAU);
            }
        }
        let (sx, sy) = (x + radius * start.cos(), y + radius * start.sin());
        match self.current {
            Some(_) => self.line_to(m, sx, sy),
            None => self.move_to(m, sx, sy),
        }
        let pieces = (sweep.abs() / (TAU / 4.0)).ceil().max(1.0) as usize;
        let step = sweep / pieces as f64;
        let k = 4.0 / 3.0 * (step / 4.0).tan();
        let mut a = start;
        for _ in 0..pieces {
            let b = a + step;
            let (ca, sa, cb, sb) = (a.cos(), a.sin(), b.cos(), b.sin());
            self.cubic_to(
                m,
                x + radius * (ca - k * sa),
                y + radius * (sa + k * ca),
                x + radius * (cb + k * sb),
                y + radius * (sb - k * cb),
                x + radius * cb,
                y + radius * sb,
            );
            a = b;
        }
    }

    /// `CGPathAddArcToPoint`: the arc of `radius` tangent to the line from the
    /// current point to `(x1, y1)` and from there to `(x2, y2)`.
    ///
    /// The tangent geometry is worked in the untransformed space the points
    /// are given in, so the current point is mapped back through `m`.
    #[allow(clippy::too_many_arguments)]
    pub fn arc_to(
        &mut self,
        m: CGAffineTransform,
        x1: f64,
        y1: f64,
        x2: f64,
        y2: f64,
        radius: f64,
    ) {
        let Some(current) = self.current else {
            return self.move_to(m, x1, y1);
        };
        let Some(inverse) = m.inverse() else {
            return;
        };
        let (x0, y0) = inverse.apply(current.0, current.1);
        let (v0x, v0y) = (x0 - x1, y0 - y1);
        let (v1x, v1y) = (x2 - x1, y2 - y1);
        let (l0, l1) = (v0x.hypot(v0y), v1x.hypot(v1y));
        let cross = v0x * v1y - v0y * v1x;
        if l0 == 0.0 || l1 == 0.0 || cross.abs() < 1e-9 || radius <= 0.0 {
            return self.line_to(m, x1, y1);
        }
        let cos = (v0x * v1x + v0y * v1y) / (l0 * l1);
        let half = cos.clamp(-1.0, 1.0).acos() / 2.0;
        let distance = radius / half.tan();
        let (t0x, t0y) = (x1 + v0x / l0 * distance, y1 + v0y / l0 * distance);
        let (t1x, t1y) = (x1 + v1x / l1 * distance, y1 + v1y / l1 * distance);
        // The centre is along the bisector, `radius / sin(half)` from the
        // corner.
        let (bx, by) = (v0x / l0 + v1x / l1, v0y / l0 + v1y / l1);
        let bl = bx.hypot(by);
        let reach = radius / half.sin();
        let (cx, cy) = (x1 + bx / bl * reach, y1 + by / bl * reach);
        let start = (t0y - cy).atan2(t0x - cx);
        let end = (t1y - cy).atan2(t1x - cx);
        self.line_to(m, t0x, t0y);
        self.arc(m, cx, cy, radius, start, end, cross > 0.0);
    }

    /// Append `other`'s elements through `m`.
    pub fn append(&mut self, m: CGAffineTransform, other: &Elements) {
        for element in &other.list {
            match *element {
                Element::Move(p) => self.move_to(m, p.0, p.1),
                Element::Line(p) => self.line_to(m, p.0, p.1),
                Element::Quad(c, p) => self.quad_to(m, c.0, c.1, p.0, p.1),
                Element::Cubic(c1, c2, p) => self.cubic_to(m, c1.0, c1.1, c2.0, c2.1, p.0, p.1),
                Element::Close => self.close(),
            }
        }
    }

    /// The bounding box of every point, control points included, as
    /// `CGPathGetBoundingBox` answers.
    pub fn bounds(&self) -> Option<CGRect> {
        let mut points = self.list.iter().flat_map(|e| match *e {
            Element::Move(p) | Element::Line(p) => vec![p],
            Element::Quad(c, p) => vec![c, p],
            Element::Cubic(c1, c2, p) => vec![c1, c2, p],
            Element::Close => vec![],
        });
        let first = points.next()?;
        let (l, b, r, t) = points.fold((first.0, first.1, first.0, first.1), |(l, b, r, t), p| {
            (l.min(p.0), b.min(p.1), r.max(p.0), t.max(p.1))
        });
        Some(CGRect {
            origin: CGPoint { x: l, y: b },
            size: CGSize {
                width: r - l,
                height: t - b,
            },
        })
    }

    /// The path for the rasterizer, or `None` when it encloses nothing.
    pub fn to_skia(&self) -> Option<tiny_skia::Path> {
        let mut builder = tiny_skia::PathBuilder::new();
        let f = |p: Point| (p.0 as f32, p.1 as f32);
        for element in &self.list {
            match *element {
                Element::Move(p) => {
                    let (x, y) = f(p);
                    builder.move_to(x, y);
                }
                Element::Line(p) => {
                    let (x, y) = f(p);
                    builder.line_to(x, y);
                }
                Element::Quad(c, p) => {
                    let ((cx, cy), (x, y)) = (f(c), f(p));
                    builder.quad_to(cx, cy, x, y);
                }
                Element::Cubic(c1, c2, p) => {
                    let ((ax, ay), (bx, by), (x, y)) = (f(c1), f(c2), f(p));
                    builder.cubic_to(ax, ay, bx, by, x, y);
                }
                Element::Close => builder.close(),
            }
        }
        builder.finish()
    }

    /// The elements of a rasterizer path, as a stroke outline comes back.
    pub fn from_skia(path: &tiny_skia::Path, m: CGAffineTransform) -> Elements {
        use tiny_skia::PathSegment;
        let mut out = Elements::default();
        let g = |p: tiny_skia::Point| (f64::from(p.x), f64::from(p.y));
        for segment in path.segments() {
            match segment {
                PathSegment::MoveTo(p) => {
                    let (x, y) = g(p);
                    out.move_to(m, x, y);
                }
                PathSegment::LineTo(p) => {
                    let (x, y) = g(p);
                    out.line_to(m, x, y);
                }
                PathSegment::QuadTo(c, p) => {
                    let ((cx, cy), (x, y)) = (g(c), g(p));
                    out.quad_to(m, cx, cy, x, y);
                }
                PathSegment::CubicTo(c1, c2, p) => {
                    let ((ax, ay), (bx, by), (x, y)) = (g(c1), g(c2), g(p));
                    out.cubic_to(m, ax, ay, bx, by, x, y);
                }
                PathSegment::Close => out.close(),
            }
        }
        out
    }
}

/// A new path object holding `elements`, which the caller owns.
pub fn path_from(elements: Elements) -> CGPathRef {
    new_path(elements, false)
}

pub fn install() {
    let path = corefoundation::base::register(c"__CGPath", None, size_of::<CGPath>(), true);
    path.replace_method(
        objc::sel::get("dealloc"),
        path_dealloc as *const c_void,
        c"v16@0:8",
    );
}

unsafe extern "C" fn path_dealloc(receiver: objc::object::Id, _sel: objc::sel::Sel) {
    // SAFETY: `-dealloc` of a `CGPath`, whose elements are this runtime's.
    unsafe {
        let path = &mut *(receiver as *mut CGPath);
        std::ptr::drop_in_place(&mut path.elements);
        objc::arc::finalize(receiver);
    }
}

/// The elements of a path object, or `None` for anything else.
pub fn elements_of<'a>(path: CGPathRef) -> Option<&'a mut Elements> {
    let class = objc::class::lookup(c"__CGPath")?;
    // SAFETY: null or an object a guest received from this runtime.
    if path.is_null() || !unsafe { corefoundation::base::is_kind_of(path.cast(), class) } {
        return None;
    }
    // SAFETY: a `CGPath`, whose elements this runtime owns.
    Some(unsafe { &mut (*path.cast_mut()).elements })
}

/// The elements a mutating call may write, or `None` for an immutable path.
///
/// Apple's headers make writing an immutable path undefined behaviour;
/// refusing is the answer that cannot corrupt the object.
fn mutable_elements(path: CGMutablePathRef) -> Option<&'static mut Elements> {
    let elements = elements_of(path)?;
    // SAFETY: the object is a `CGPath` this runtime made.
    match unsafe { (*path).mutable } {
        true => Some(elements),
        false => None,
    }
}

fn new_path(elements: Elements, mutable: bool) -> CGPathRef {
    let class = objc::class::lookup(c"__CGPath").expect("installed during bootstrap");
    // SAFETY: `CGPath` is the registered class layout.
    let path = unsafe { corefoundation::base::allocate::<CGPath>(class) };
    // SAFETY: a fresh allocation. The elements are written rather than left
    // zeroed, because a zeroed `Vec` is not an empty one.
    unsafe {
        (*path).mutable = mutable;
        (*path).elements = elements;
    }
    path
}

/// The transform a path call was given, or the identity for none.
fn transform(m: *const CGAffineTransform) -> CGAffineTransform {
    match m.is_null() {
        true => CGAffineTransformIdentity,
        // SAFETY: the caller's transform.
        false => unsafe { *m },
    }
}

pub unsafe extern "C" fn CGPathCreateMutable() -> CGMutablePathRef {
    new_path(Elements::default(), true).cast_mut()
}

pub unsafe extern "C" fn CGPathCreateCopy(path: CGPathRef) -> CGPathRef {
    elements_of(path).map_or(std::ptr::null(), |e| new_path(e.clone(), false))
}

pub unsafe extern "C" fn CGPathCreateMutableCopy(path: CGPathRef) -> CGMutablePathRef {
    elements_of(path).map_or(std::ptr::null_mut(), |e| {
        new_path(e.clone(), true).cast_mut()
    })
}

pub unsafe extern "C" fn CGPathCreateCopyByTransformingPath(
    path: CGPathRef,
    m: *const CGAffineTransform,
) -> CGPathRef {
    let Some(source) = elements_of(path) else {
        return std::ptr::null();
    };
    let mut out = Elements::default();
    out.append(transform(m), source);
    new_path(out, false)
}

pub unsafe extern "C" fn CGPathCreateMutableCopyByTransformingPath(
    path: CGPathRef,
    m: *const CGAffineTransform,
) -> CGMutablePathRef {
    let Some(source) = elements_of(path) else {
        return std::ptr::null_mut();
    };
    let mut out = Elements::default();
    out.append(transform(m), source);
    new_path(out, true).cast_mut()
}

pub unsafe extern "C" fn CGPathCreateWithRect(
    rect: CGRect,
    m: *const CGAffineTransform,
) -> CGPathRef {
    let mut out = Elements::default();
    out.rect(transform(m), rect);
    new_path(out, false)
}

pub unsafe extern "C" fn CGPathCreateWithEllipseInRect(
    rect: CGRect,
    m: *const CGAffineTransform,
) -> CGPathRef {
    let mut out = Elements::default();
    out.ellipse(transform(m), rect);
    new_path(out, false)
}

/// `CGPathRef CGPathCreateWithRoundedRect(CGRect rect, CGFloat cornerWidth,
/// CGFloat cornerHeight, const CGAffineTransform *m)`
pub unsafe extern "C" fn CGPathCreateWithRoundedRect(
    rect: CGRect,
    corner_width: f64,
    corner_height: f64,
    m: *const CGAffineTransform,
) -> CGPathRef {
    let mut out = Elements::default();
    out.rounded_rect(transform(m), rect, corner_width, corner_height);
    new_path(out, false)
}

/// `CGPathRef CGPathCreateCopyByDashingPath(CGPathRef path,
/// const CGAffineTransform *m, CGFloat phase, const CGFloat *lengths,
/// size_t count)`
pub unsafe extern "C" fn CGPathCreateCopyByDashingPath(
    path: CGPathRef,
    m: *const CGAffineTransform,
    phase: f64,
    lengths: *const f64,
    count: usize,
) -> CGPathRef {
    let Some(source) = elements_of(path) else {
        return std::ptr::null();
    };
    if lengths.is_null() || count == 0 {
        return std::ptr::null();
    }
    // SAFETY: the caller supplies `count` lengths.
    let lengths = unsafe { std::slice::from_raw_parts(lengths, count) };
    let widths: Vec<f32> = lengths.iter().map(|l| *l as f32).collect();
    let Some(dash) = tiny_skia::StrokeDash::new(widths, phase as f32) else {
        return std::ptr::null();
    };
    // The transform is applied before the dashing, as the header says.
    let mut moved = Elements::default();
    moved.append(transform(m), source);
    let Some(skia) = moved.to_skia() else {
        return std::ptr::null();
    };
    let Some(dashed) = skia.dash(&dash, 1.0) else {
        return std::ptr::null();
    };
    new_path(
        Elements::from_skia(&dashed, CGAffineTransformIdentity),
        false,
    )
}

/// `CGPathRef CGPathCreateCopyByStrokingPath(CGPathRef path,
/// const CGAffineTransform *m, CGFloat lineWidth, CGLineCap lineCap,
/// CGLineJoin lineJoin, CGFloat miterLimit)`
pub unsafe extern "C" fn CGPathCreateCopyByStrokingPath(
    path: CGPathRef,
    m: *const CGAffineTransform,
    line_width: f64,
    line_cap: i32,
    line_join: i32,
    miter_limit: f64,
) -> CGPathRef {
    let Some(source) = elements_of(path) else {
        return std::ptr::null();
    };
    let mut moved = Elements::default();
    moved.append(transform(m), source);
    let Some(skia) = moved.to_skia() else {
        return std::ptr::null();
    };
    let style = tiny_skia::Stroke {
        width: line_width as f32,
        miter_limit: miter_limit as f32,
        line_cap: match line_cap {
            1 => tiny_skia::LineCap::Round,
            2 => tiny_skia::LineCap::Square,
            _ => tiny_skia::LineCap::Butt,
        },
        line_join: match line_join {
            1 => tiny_skia::LineJoin::Round,
            2 => tiny_skia::LineJoin::Bevel,
            _ => tiny_skia::LineJoin::Miter,
        },
        ..tiny_skia::Stroke::default()
    };
    let Some(outline) = skia.stroke(&style, 1.0) else {
        return std::ptr::null();
    };
    new_path(
        Elements::from_skia(&outline, CGAffineTransformIdentity),
        false,
    )
}

pub unsafe extern "C" fn CGPathRetain(path: CGPathRef) -> CGPathRef {
    if !path.is_null() {
        // SAFETY: a path the caller holds.
        unsafe { corefoundation::api::CFRetain(path.cast()) };
    }
    path
}

pub unsafe extern "C" fn CGPathRelease(path: CGPathRef) {
    if !path.is_null() {
        // SAFETY: a reference the caller owns.
        unsafe { corefoundation::api::CFRelease(path.cast()) };
    }
}

pub unsafe extern "C" fn CGPathMoveToPoint(
    path: CGMutablePathRef,
    m: *const CGAffineTransform,
    x: f64,
    y: f64,
) {
    if let Some(e) = mutable_elements(path) {
        e.move_to(transform(m), x, y);
    }
}

pub unsafe extern "C" fn CGPathAddLineToPoint(
    path: CGMutablePathRef,
    m: *const CGAffineTransform,
    x: f64,
    y: f64,
) {
    if let Some(e) = mutable_elements(path) {
        e.line_to(transform(m), x, y);
    }
}

pub unsafe extern "C" fn CGPathAddQuadCurveToPoint(
    path: CGMutablePathRef,
    m: *const CGAffineTransform,
    cx: f64,
    cy: f64,
    x: f64,
    y: f64,
) {
    if let Some(e) = mutable_elements(path) {
        e.quad_to(transform(m), cx, cy, x, y);
    }
}

#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn CGPathAddCurveToPoint(
    path: CGMutablePathRef,
    m: *const CGAffineTransform,
    c1x: f64,
    c1y: f64,
    c2x: f64,
    c2y: f64,
    x: f64,
    y: f64,
) {
    if let Some(e) = mutable_elements(path) {
        e.cubic_to(transform(m), c1x, c1y, c2x, c2y, x, y);
    }
}

pub unsafe extern "C" fn CGPathCloseSubpath(path: CGMutablePathRef) {
    if let Some(e) = mutable_elements(path) {
        e.close();
    }
}

pub unsafe extern "C" fn CGPathAddRect(
    path: CGMutablePathRef,
    m: *const CGAffineTransform,
    rect: CGRect,
) {
    if let Some(e) = mutable_elements(path) {
        e.rect(transform(m), rect);
    }
}

pub unsafe extern "C" fn CGPathAddRects(
    path: CGMutablePathRef,
    m: *const CGAffineTransform,
    rects: *const CGRect,
    count: usize,
) {
    let Some(e) = mutable_elements(path) else {
        return;
    };
    if rects.is_null() {
        return;
    }
    // SAFETY: the caller supplies `count` rectangles.
    for rect in unsafe { std::slice::from_raw_parts(rects, count) } {
        e.rect(transform(m), *rect);
    }
}

pub unsafe extern "C" fn CGPathAddEllipseInRect(
    path: CGMutablePathRef,
    m: *const CGAffineTransform,
    rect: CGRect,
) {
    if let Some(e) = mutable_elements(path) {
        e.ellipse(transform(m), rect);
    }
}

/// `void CGPathAddRoundedRect(CGMutablePathRef path, const CGAffineTransform
/// *m, CGRect rect, CGFloat cornerWidth, CGFloat cornerHeight)`
pub unsafe extern "C" fn CGPathAddRoundedRect(
    path: CGMutablePathRef,
    m: *const CGAffineTransform,
    rect: CGRect,
    corner_width: f64,
    corner_height: f64,
) {
    if let Some(e) = mutable_elements(path) {
        e.rounded_rect(transform(m), rect, corner_width, corner_height);
    }
}

#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn CGPathAddArc(
    path: CGMutablePathRef,
    m: *const CGAffineTransform,
    x: f64,
    y: f64,
    radius: f64,
    start: f64,
    end: f64,
    clockwise: bool,
) {
    if let Some(e) = mutable_elements(path) {
        e.arc(transform(m), x, y, radius, start, end, clockwise);
    }
}

#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn CGPathAddArcToPoint(
    path: CGMutablePathRef,
    m: *const CGAffineTransform,
    x1: f64,
    y1: f64,
    x2: f64,
    y2: f64,
    radius: f64,
) {
    if let Some(e) = mutable_elements(path) {
        e.arc_to(transform(m), x1, y1, x2, y2, radius);
    }
}

/// `void CGPathAddRelativeArc(CGMutablePathRef path, const CGAffineTransform
/// *m, CGFloat x, CGFloat y, CGFloat radius, CGFloat startAngle, CGFloat delta)`
pub unsafe extern "C" fn CGPathAddRelativeArc(
    path: CGMutablePathRef,
    m: *const CGAffineTransform,
    x: f64,
    y: f64,
    radius: f64,
    start: f64,
    delta: f64,
) {
    if let Some(e) = mutable_elements(path) {
        e.arc(
            transform(m),
            x,
            y,
            radius,
            start,
            start + delta,
            delta < 0.0,
        );
    }
}

pub unsafe extern "C" fn CGPathAddLines(
    path: CGMutablePathRef,
    m: *const CGAffineTransform,
    points: *const CGPoint,
    count: usize,
) {
    let Some(e) = mutable_elements(path) else {
        return;
    };
    if points.is_null() || count == 0 {
        return;
    }
    // SAFETY: the caller supplies `count` points.
    let points = unsafe { std::slice::from_raw_parts(points, count) };
    e.move_to(transform(m), points[0].x, points[0].y);
    for p in &points[1..] {
        e.line_to(transform(m), p.x, p.y);
    }
}

pub unsafe extern "C" fn CGPathAddPath(
    path: CGMutablePathRef,
    m: *const CGAffineTransform,
    other: CGPathRef,
) {
    let Some(source) = elements_of(other).map(|e| e.clone()) else {
        return;
    };
    if let Some(e) = mutable_elements(path) {
        e.append(transform(m), &source);
    }
}

pub unsafe extern "C" fn CGPathIsEmpty(path: CGPathRef) -> bool {
    elements_of(path).is_none_or(|e| e.is_empty())
}

/// `bool CGPathIsRect(CGPathRef path, CGRect *rect)`
pub unsafe extern "C" fn CGPathIsRect(path: CGPathRef, rect: *mut CGRect) -> bool {
    let Some(elements) = elements_of(path) else {
        return false;
    };
    let Some(found) = elements.as_rect() else {
        return false;
    };
    if !rect.is_null() {
        // SAFETY: the caller's out-parameter.
        unsafe { *rect = found };
    }
    true
}

pub unsafe extern "C" fn CGPathGetBoundingBox(path: CGPathRef) -> CGRect {
    elements_of(path)
        .and_then(|e| e.bounds())
        .unwrap_or(NULL_RECT)
}

/// `CGPathGetPathBoundingBox`, which leaves the control points out. The
/// rasterizer's tight bounds are exactly that.
pub unsafe extern "C" fn CGPathGetPathBoundingBox(path: CGPathRef) -> CGRect {
    let Some(skia) = elements_of(path).and_then(|e| e.to_skia()) else {
        return NULL_RECT;
    };
    let tight = skia.compute_tight_bounds().unwrap_or(skia.bounds());
    CGRect {
        origin: CGPoint {
            x: f64::from(tight.left()),
            y: f64::from(tight.top()),
        },
        size: CGSize {
            width: f64::from(tight.width()),
            height: f64::from(tight.height()),
        },
    }
}

pub unsafe extern "C" fn CGPathGetCurrentPoint(path: CGPathRef) -> CGPoint {
    elements_of(path)
        .and_then(|e| e.current)
        .map_or(CGPoint::default(), |(x, y)| CGPoint { x, y })
}

/// `bool CGPathContainsPoint(CGPathRef, const CGAffineTransform *, CGPoint,
/// bool eoFill)`: whether the point's pixel would be filled.
pub unsafe extern "C" fn CGPathContainsPoint(
    path: CGPathRef,
    m: *const CGAffineTransform,
    point: CGPoint,
    even_odd: bool,
) -> bool {
    let Some(source) = elements_of(path) else {
        return false;
    };
    let mut moved = Elements::default();
    moved.append(transform(m), source);
    let Some(skia) = moved.to_skia() else {
        return false;
    };
    // Rasterize one pixel centred on the point, without antialiasing.
    let Some(mut mask) = tiny_skia::Mask::new(1, 1) else {
        return false;
    };
    let rule = match even_odd {
        true => tiny_skia::FillRule::EvenOdd,
        false => tiny_skia::FillRule::Winding,
    };
    let shift =
        tiny_skia::Transform::from_translate((0.5 - point.x) as f32, (0.5 - point.y) as f32);
    mask.fill_path(&skia, rule, false, shift);
    mask.data()[0] != 0
}

/// `bool CGPathEqualToPath(CGPathRef path1, CGPathRef path2)`
pub unsafe extern "C" fn CGPathEqualToPath(path1: CGPathRef, path2: CGPathRef) -> bool {
    match (elements_of(path1), elements_of(path2)) {
        (Some(a), Some(b)) => a == b,
        (None, None) => true,
        _ => false,
    }
}

/// `void CGPathApply(CGPathRef, void *info, CGPathApplierFunction)`
pub unsafe extern "C" fn CGPathApply(
    path: CGPathRef,
    info: *mut c_void,
    function: Option<unsafe extern "C" fn(*mut c_void, *const CGPathElement)>,
) {
    let (Some(elements), Some(function)) = (elements_of(path), function) else {
        return;
    };
    let list = elements.list.clone();
    let p = |(x, y): Point| CGPoint { x, y };
    for element in list {
        let (element_type, points): (CGPathElementType, Vec<CGPoint>) = match element {
            Element::Move(a) => (CGPathElementType::kCGPathElementMoveToPoint, vec![p(a)]),
            Element::Line(a) => (CGPathElementType::kCGPathElementAddLineToPoint, vec![p(a)]),
            Element::Quad(c, a) => (
                CGPathElementType::kCGPathElementAddQuadCurveToPoint,
                vec![p(c), p(a)],
            ),
            Element::Cubic(c1, c2, a) => (
                CGPathElementType::kCGPathElementAddCurveToPoint,
                vec![p(c1), p(c2), p(a)],
            ),
            Element::Close => (CGPathElementType::kCGPathElementCloseSubpath, vec![]),
        };
        let element = CGPathElement {
            element_type,
            points: points.as_ptr(),
        };
        // SAFETY: the applier's declared signature, and an element that lives
        // across the call.
        unsafe { function(info, &element) };
    }
}

/// `void CGPathApplyWithBlock(CGPathRef path, CGPathApplierBlock block)`
///
/// The block's invoke pointer must already be host-callable; a guest block
/// reaches that state through the runtime's block substitution.
pub unsafe extern "C" fn CGPathApplyWithBlock(path: CGPathRef, block: *const c_void) {
    let Some(elements) = elements_of(path) else {
        return;
    };
    let Some(invoke) = (unsafe { objc::block::invoke(block.cast_mut()) }) else {
        return;
    };
    // SAFETY: the block's declared signature is `void (^)(const CGPathElement *)`.
    let call: unsafe extern "C" fn(*mut c_void, *const CGPathElement) =
        unsafe { std::mem::transmute(invoke) };
    let list = elements.list.clone();
    let p = |(x, y): Point| CGPoint { x, y };
    for element in list {
        let (element_type, points): (CGPathElementType, Vec<CGPoint>) = match element {
            Element::Move(a) => (CGPathElementType::kCGPathElementMoveToPoint, vec![p(a)]),
            Element::Line(a) => (CGPathElementType::kCGPathElementAddLineToPoint, vec![p(a)]),
            Element::Quad(c, a) => (
                CGPathElementType::kCGPathElementAddQuadCurveToPoint,
                vec![p(c), p(a)],
            ),
            Element::Cubic(c1, c2, a) => (
                CGPathElementType::kCGPathElementAddCurveToPoint,
                vec![p(c1), p(c2), p(a)],
            ),
            Element::Close => (CGPathElementType::kCGPathElementCloseSubpath, vec![]),
        };
        let element = CGPathElement {
            element_type,
            points: points.as_ptr(),
        };
        // SAFETY: the block, and an element that lives across the call.
        unsafe { call(block.cast_mut(), &element) };
    }
}

/// `CFTypeID CGPathGetTypeID(void)`
pub unsafe extern "C" fn CGPathGetTypeID() -> corefoundation::base::CFTypeID {
    let Some(class) = objc::class::lookup(c"__CGPath") else {
        return 0;
    };
    corefoundation::base::type_id(class)
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
        "CGPathCreateMutable" => CGPathCreateMutable,
        "CGPathCreateCopy" => CGPathCreateCopy,
        "CGPathCreateMutableCopy" => CGPathCreateMutableCopy,
        "CGPathCreateCopyByTransformingPath" => CGPathCreateCopyByTransformingPath,
        "CGPathCreateMutableCopyByTransformingPath" => CGPathCreateMutableCopyByTransformingPath,
        "CGPathCreateWithRect" => CGPathCreateWithRect,
        "CGPathCreateWithEllipseInRect" => CGPathCreateWithEllipseInRect,
        "CGPathCreateWithRoundedRect" => CGPathCreateWithRoundedRect,
        "CGPathCreateCopyByDashingPath" => CGPathCreateCopyByDashingPath,
        "CGPathCreateCopyByStrokingPath" => CGPathCreateCopyByStrokingPath,
        "CGPathRetain" => CGPathRetain,
        "CGPathRelease" => CGPathRelease,
        "CGPathMoveToPoint" => CGPathMoveToPoint,
        "CGPathAddLineToPoint" => CGPathAddLineToPoint,
        "CGPathAddQuadCurveToPoint" => CGPathAddQuadCurveToPoint,
        "CGPathAddCurveToPoint" => CGPathAddCurveToPoint,
        "CGPathCloseSubpath" => CGPathCloseSubpath,
        "CGPathAddRect" => CGPathAddRect,
        "CGPathAddRects" => CGPathAddRects,
        "CGPathAddEllipseInRect" => CGPathAddEllipseInRect,
        "CGPathAddRoundedRect" => CGPathAddRoundedRect,
        "CGPathAddArc" => CGPathAddArc,
        "CGPathAddArcToPoint" => CGPathAddArcToPoint,
        "CGPathAddRelativeArc" => CGPathAddRelativeArc,
        "CGPathAddLines" => CGPathAddLines,
        "CGPathAddPath" => CGPathAddPath,
        "CGPathIsEmpty" => CGPathIsEmpty,
        "CGPathIsRect" => CGPathIsRect,
        "CGPathGetBoundingBox" => CGPathGetBoundingBox,
        "CGPathGetPathBoundingBox" => CGPathGetPathBoundingBox,
        "CGPathGetCurrentPoint" => CGPathGetCurrentPoint,
        "CGPathContainsPoint" => CGPathContainsPoint,
        "CGPathEqualToPath" => CGPathEqualToPath,
        "CGPathApply" => CGPathApply,
        "CGPathApplyWithBlock" => CGPathApplyWithBlock,
        "CGPathGetTypeID" => CGPathGetTypeID,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn count(info: *mut c_void, element: *const CGPathElement) {
        // SAFETY: a `Vec<CGPathElementType>` the test passed, and a live element.
        unsafe { (*(info as *mut Vec<CGPathElementType>)).push((*element).element_type) };
    }

    /// A rectangle is a move, three lines and a close, which is what a program
    /// walking it with `CGPathApply` expects.
    #[test]
    fn a_rect_applies_as_move_three_lines_and_close() {
        crate::bootstrap();
        let mut kinds: Vec<CGPathElementType> = Vec::new();
        // SAFETY: a path this test made, and an applier for `kinds`.
        unsafe {
            let path = CGPathCreateMutable();
            CGPathAddRect(
                path,
                std::ptr::null(),
                CGRect {
                    origin: CGPoint { x: 1.0, y: 2.0 },
                    size: CGSize {
                        width: 3.0,
                        height: 4.0,
                    },
                },
            );
            CGPathApply(path, (&raw mut kinds).cast(), Some(count));
            assert_eq!(
                CGPathGetBoundingBox(path),
                CGRect {
                    origin: CGPoint { x: 1.0, y: 2.0 },
                    size: CGSize {
                        width: 3.0,
                        height: 4.0
                    },
                }
            );
            assert!(CGPathContainsPoint(
                path,
                std::ptr::null(),
                CGPoint { x: 2.0, y: 3.0 },
                false
            ));
            assert!(!CGPathContainsPoint(
                path,
                std::ptr::null(),
                CGPoint { x: 9.0, y: 3.0 },
                false
            ));
            CGPathRelease(path);
        }
        assert_eq!(
            kinds,
            [
                CGPathElementType::kCGPathElementMoveToPoint,
                CGPathElementType::kCGPathElementAddLineToPoint,
                CGPathElementType::kCGPathElementAddLineToPoint,
                CGPathElementType::kCGPathElementAddLineToPoint,
                CGPathElementType::kCGPathElementCloseSubpath,
            ]
        );
    }

    /// A quarter arc ends where the angles say, whichever way it turns.
    #[test]
    fn an_arc_ends_at_its_end_angle() {
        let mut e = Elements::default();
        e.arc(
            CGAffineTransformIdentity,
            0.0,
            0.0,
            10.0,
            0.0,
            std::f64::consts::FRAC_PI_2,
            false,
        );
        let end = e.current.expect("a current point");
        assert!((end.0).abs() < 1e-9 && (end.1 - 10.0).abs() < 1e-9);
    }

    /// A rounded rectangle covers the rectangle it was given, corners included.
    #[test]
    fn a_rounded_rect_has_the_rects_bounds() {
        let mut e = Elements::default();
        e.rounded_rect(
            CGAffineTransformIdentity,
            CGRect {
                origin: CGPoint { x: 0.0, y: 0.0 },
                size: CGSize {
                    width: 10.0,
                    height: 10.0,
                },
            },
            2.0,
            2.0,
        );
        assert!(!e.is_empty());
        assert_eq!(
            e.bounds(),
            Some(CGRect {
                origin: CGPoint { x: 0.0, y: 0.0 },
                size: CGSize {
                    width: 10.0,
                    height: 10.0,
                },
            })
        );
    }

    /// Only a path that is exactly one axis-aligned rectangle answers with it.
    #[test]
    fn only_a_rect_is_a_rect() {
        let mut rect = Elements::default();
        rect.rect(
            CGAffineTransformIdentity,
            CGRect {
                origin: CGPoint { x: 1.0, y: 2.0 },
                size: CGSize {
                    width: 3.0,
                    height: 4.0,
                },
            },
        );
        assert_eq!(
            rect.as_rect(),
            Some(CGRect {
                origin: CGPoint { x: 1.0, y: 2.0 },
                size: CGSize {
                    width: 3.0,
                    height: 4.0,
                },
            })
        );

        let mut triangle = Elements::default();
        triangle.move_to(CGAffineTransformIdentity, 0.0, 0.0);
        triangle.line_to(CGAffineTransformIdentity, 1.0, 0.0);
        triangle.line_to(CGAffineTransformIdentity, 0.0, 1.0);
        triangle.close();
        assert_eq!(triangle.as_rect(), None);
    }
}
