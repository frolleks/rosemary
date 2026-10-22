#![allow(non_camel_case_types, non_snake_case)]
use corefoundation::base::CFRuntimeBase;

pub type CGFloat = f64;

fn concat(t1: CGAffineTransform, t2: CGAffineTransform) -> CGAffineTransform {
    CGAffineTransform {
        a: t1.a * t2.a + t1.b * t2.c,
        b: t1.a * t2.b + t1.b * t2.d,
        c: t1.c * t2.a + t1.d * t2.c,
        d: t1.c * t2.b + t1.d * t2.d,
        tx: t1.tx * t2.a + t1.ty * t2.c + t2.tx,
        ty: t1.tx * t2.b + t1.ty * t2.d + t2.ty,
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub enum CGPathElementType {
    kCGPathElementMoveToPoint,
    kCGPathElementAddLineToPoint,
    kCGPathElementAddQuadCurveToPoint,
    kCGPathElementAddCurveToPoint,
    kCGPathElementCloseSubpath,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CGSize {
    pub width: CGFloat,
    pub height: CGFloat,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CGVector {
    pub dx: CGFloat,
    pub dy: CGFloat,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CGPoint {
    pub x: CGFloat,
    pub y: CGFloat,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CGRect {
    pub origin: CGPoint,
    pub size: CGSize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CGAffineTransform {
    pub a: CGFloat,
    pub b: CGFloat,
    pub c: CGFloat,
    pub d: CGFloat,
    pub tx: CGFloat,
    pub ty: CGFloat,
}

impl CGAffineTransform {
    /// `self` then `then`, as `CGAffineTransformConcat(self, then)`.
    pub fn then(self, then: CGAffineTransform) -> CGAffineTransform {
        CGAffineTransform {
            a: self.a * then.a + self.b * then.c,
            b: self.a * then.b + self.b * then.d,
            c: self.c * then.a + self.d * then.c,
            d: self.c * then.b + self.d * then.d,
            tx: self.tx * then.a + self.ty * then.c + then.tx,
            ty: self.tx * then.b + self.ty * then.d + then.ty,
        }
    }

    pub fn apply(self, x: f64, y: f64) -> (f64, f64) {
        (
            self.a * x + self.c * y + self.tx,
            self.b * x + self.d * y + self.ty,
        )
    }

    /// The inverse, or `None` for a singular transform.
    pub fn inverse(self) -> Option<CGAffineTransform> {
        let det = self.a * self.d - self.b * self.c;
        if det == 0.0 || !det.is_finite() {
            return None;
        }
        let (a, b, c, d) = (self.d / det, -self.b / det, -self.c / det, self.a / det);
        Some(CGAffineTransform {
            a,
            b,
            c,
            d,
            tx: -(self.tx * a + self.ty * c),
            ty: -(self.tx * b + self.ty * d),
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CGAffineTransformComponents {
    pub horizontal_sheer: CGFloat,
    pub rotation: CGFloat,
    pub scale: CGSize,
    pub translation: CGVector,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct CGPathElement {
    pub element_type: CGPathElementType,
    pub points: Vec<CGPoint>,
}

#[repr(C)]
pub struct CGPath {
    base: CFRuntimeBase,
    mutable: bool,
    elements: Vec<CGPathElement>,
}

pub type CGPathRef = *const CGPath;
pub type CGMutablePathRef = *mut CGPath;

pub static CGAffineTransformIdentity: CGAffineTransform = CGAffineTransform {
    a: 1.0,
    b: 0.0,
    c: 0.0,
    d: 1.0,
    tx: 0.0,
    ty: 0.0,
};

pub unsafe extern "C" fn CGAffineTransformMake(
    a: CGFloat,
    b: CGFloat,
    c: CGFloat,
    d: CGFloat,
    tx: CGFloat,
    ty: CGFloat,
) -> CGAffineTransform {
    CGAffineTransform { a, b, c, d, tx, ty }
}

pub unsafe extern "C" fn CGAffineTransformMakeRotation(angle: CGFloat) -> CGAffineTransform {
    let (s, c) = angle.sin_cos();
    CGAffineTransform {
        a: c,
        b: s,
        c: -s,
        d: c,
        tx: 0.0,
        ty: 0.0,
    }
}

pub unsafe extern "C" fn CGAffineTransformMakeScale(sx: CGFloat, sy: CGFloat) -> CGAffineTransform {
    CGAffineTransform {
        a: sx,
        b: 0.0,
        c: 0.0,
        d: sy,
        tx: 0.0,
        ty: 0.0,
    }
}

pub unsafe extern "C" fn CGAffineTransformMakeTranslation(
    tx: CGFloat,
    ty: CGFloat,
) -> CGAffineTransform {
    CGAffineTransform {
        a: 1.0,
        b: 0.0,
        c: 0.0,
        d: 1.0,
        tx,
        ty,
    }
}

pub unsafe extern "C" fn CGAffineTransformRotate(
    t: CGAffineTransform,
    angle: CGFloat,
) -> CGAffineTransform {
    concat(unsafe { CGAffineTransformMakeRotation(angle) }, t)
}

pub unsafe extern "C" fn CGAffineTransformScale(
    t: CGAffineTransform,
    sx: CGFloat,
    sy: CGFloat,
) -> CGAffineTransform {
    concat(unsafe { CGAffineTransformMakeScale(sx, sy) }, t)
}

pub unsafe extern "C" fn CGAffineTransformTranslate(
    t: CGAffineTransform,
    tx: CGFloat,
    ty: CGFloat,
) -> CGAffineTransform {
    concat(unsafe { CGAffineTransformMakeTranslation(tx, ty) }, t)
}

pub unsafe extern "C" fn CGAffineTransformConcat(
    t1: CGAffineTransform,
    t2: CGAffineTransform,
) -> CGAffineTransform {
    concat(t1, t2)
}

pub unsafe extern "C" fn CGAffineTransformInvert(t: CGAffineTransform) -> CGAffineTransform {
    let det = t.a * t.d - t.b * t.c;
    if det == 0.0 || !det.is_finite() {
        return t;
    }
    CGAffineTransform {
        a: t.d / det,
        b: -t.b / det,
        c: -t.c / det,
        d: t.a / det,
        tx: (t.c * t.ty - t.d * t.tx) / det,
        ty: (t.b * t.tx - t.a * t.ty) / det,
    }
}

pub unsafe extern "C" fn CGAffineTransformIsIdentity(t: CGAffineTransform) -> bool {
    t == CGAffineTransformIdentity
}

pub unsafe extern "C" fn CGAffineTransformEqualToTransform(
    t1: CGAffineTransform,
    t2: CGAffineTransform,
) -> bool {
    t1 == t2
}

/// Register the classes a Core Graphics object is, once.
///
/// Called from [`data_symbols`] the way `appkit::bootstrap` is: the provider is
/// built before anything can ask for a class, so this has to have run by then.
pub fn bootstrap() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // Each module that owns a class registers it here as it arrives:
        //   graphics::install()   __CGColorSpace, __CGDataProvider,
        //                         __CGImage, __CGImageSource
        //   cgcontext::install()  __CGContext, __CGColor
        //   cgpath::install()     __CGPath
        //   cgpaint::install()    __CGPattern, __CGFunction, __CGShading,
        //                         __CGLayer
    });
}

/// The data symbols this framework publishes, in the Mach-O spelling.
///
/// [`exports!`]'s `data` section feeds `provide()` only; a `dlsym` of a
/// variable goes through here, so the two must name the same addresses.
pub fn data_symbols() -> Vec<(String, u64)> {
    bootstrap();
    vec![(
        "_CGAffineTransformIdentity".to_string(),
        (&raw const CGAffineTransformIdentity) as usize as u64,
    )]
}

exports::exports! {
    functions {
        "CGAffineTransformMake" => CGAffineTransformMake,
        "CGAffineTransformMakeRotation" => CGAffineTransformMakeRotation,
        "CGAffineTransformMakeScale" => CGAffineTransformMakeScale,
        "CGAffineTransformMakeTranslation" => CGAffineTransformMakeTranslation,
        "CGAffineTransformRotate" => CGAffineTransformRotate,
        "CGAffineTransformScale" => CGAffineTransformScale,
        "CGAffineTransformTranslate" => CGAffineTransformTranslate,
        "CGAffineTransformInvert" => CGAffineTransformInvert,
        "CGAffineTransformConcat" => CGAffineTransformConcat,
        "CGAffineTransformIsIdentity" => CGAffineTransformIsIdentity,
        "CGAffineTransformEqualToTransform" => CGAffineTransformEqualToTransform,
    }
    data {
        "_CGAffineTransformIdentity" => &raw const CGAffineTransformIdentity as u64,
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_identity_is_published_and_points_at_its_fields() {
        let symbols = data_symbols();
        let (_, identity) = symbols
            .iter()
            .find(|(name, _)| name == "_CGAffineTransformIdentity")
            .expect("published");
        // SAFETY: the symbol points at the six-double static above.
        let fields = unsafe { std::slice::from_raw_parts(*identity as *const f64, 6) };
        assert_eq!(fields, &[1.0, 0.0, 0.0, 1.0, 0.0, 0.0]);
    }
}
