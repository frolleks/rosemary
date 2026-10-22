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

#[unsafe(no_mangle)]
pub static CGAffineTransformIdentity: CGAffineTransform = CGAffineTransform {
    a: 1.0,
    b: 0.0,
    c: 0.0,
    d: 1.0,
    tx: 0.0,
    ty: 0.0,
};

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn CGAffineTransformRotate(
    t: CGAffineTransform,
    angle: CGFloat,
) -> CGAffineTransform {
    concat(unsafe { CGAffineTransformMakeRotation(angle) }, t)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn CGAffineTransformScale(
    t: CGAffineTransform,
    sx: CGFloat,
    sy: CGFloat,
) -> CGAffineTransform {
    concat(unsafe { CGAffineTransformMakeScale(sx, sy) }, t)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn CGAffineTransformTranslate(
    t: CGAffineTransform,
    tx: CGFloat,
    ty: CGFloat,
) -> CGAffineTransform {
    concat(unsafe { CGAffineTransformMakeTranslation(tx, ty) }, t)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn CGAffineTransformConcat(
    t1: CGAffineTransform,
    t2: CGAffineTransform,
) -> CGAffineTransform {
    concat(t1, t2)
}

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn CGAffineTransformIsIdentity(t: CGAffineTransform) -> bool {
    t == CGAffineTransformIdentity
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn CGAffineTransformEqualToTransform(
    t1: CGAffineTransform,
    t2: CGAffineTransform,
) -> bool {
    t1 == t2
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn CGPathCreateWithRect(
    rect: CGRect,
    transform: *const CGAffineTransform,
) -> CGPathRef {
    todo!()
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
        "CGAffineTransformIdentity" => &raw const CGAffineTransformIdentity as u64,
    }
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
