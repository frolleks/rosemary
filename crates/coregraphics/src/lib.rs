#![allow(
    clippy::missing_safety_doc,
    clippy::not_unsafe_ptr_arg_deref,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]
use corefoundation::base::CFRuntimeBase;

pub mod cgaffinetransform;
pub mod cgpath;

pub use cgaffinetransform::*;

pub type CGFloat = f64;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CGPathElementType {
    kCGPathElementMoveToPoint(CGPoint),
    kCGPathElementAddLineToPoint(CGPoint),
    kCGPathElementAddQuadCurveToPoint(CGPoint, CGPoint),
    kCGPathElementAddCurveToPoint(CGPoint, CGPoint, CGPoint),
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

/// `CGPathElement`: a type and a pointer to its points, as `CGPathApply`
/// hands one to an applier.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CGPathElement {
    pub element_type: CGPathElementType,
    pub points: *const CGPoint,
}

/// A `CGPath`: its elements, in the coordinates they were added in.
///
/// `base` is first so the object is an Objective-C one, which is what
/// `CFRetain`/`CFRelease` and `-isEqual:` go through.
#[repr(C)]
pub struct CGPath {
    pub(crate) base: CFRuntimeBase,
    pub(crate) mutable: bool,
    pub(crate) elements: cgpath::Elements,
}

pub type CGPathRef = *const CGPath;
pub type CGMutablePathRef = *mut CGPath;

/// Register the classes a Core Graphics object is, once.
///
/// Called from [`data_symbols`] the way `appkit::bootstrap` is: the provider is
/// built before anything can ask for a class, so this has to have run by then.
pub fn bootstrap() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        cgpath::install();
        // Each module that owns a class registers it here as it arrives:
        //   graphics::install()   __CGColorSpace, __CGDataProvider,
        //                         __CGImage, __CGImageSource
        //   cgcontext::install()  __CGContext, __CGColor
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
    groups {
        cgaffinetransform,
        cgpath,
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
