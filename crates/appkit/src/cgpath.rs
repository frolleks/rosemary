//! The path type, from `coregraphics`, and the glyph outlines this crate
//! builds with it.

pub use coregraphics::cgpath::{Elements, elements_of, path_from};

use coregraphics::{CGPoint, CGRect, CGSize};
use foundation::geometry::{NSPoint, NSRect, NSSize};

use crate::cgcontext::CGAffineTransform;

/// `NSRect` as the `CGRect` the path builder takes. AppKit's C signatures keep
/// the `NS` spelling, and the two are the same layout.
pub(crate) fn cg_rect(r: NSRect) -> CGRect {
    CGRect {
        origin: CGPoint {
            x: r.origin.x,
            y: r.origin.y,
        },
        size: CGSize {
            width: r.size.width,
            height: r.size.height,
        },
    }
}

/// `CGRect` as the `NSRect` AppKit's C signatures answer with.
pub(crate) fn ns_rect(r: CGRect) -> NSRect {
    NSRect {
        origin: NSPoint {
            x: r.origin.x,
            y: r.origin.y,
        },
        size: NSSize {
            width: r.size.width,
            height: r.size.height,
        },
    }
}

/// Append a glyph's outline, in font units, through `m`. Every contour is
/// closed, as a glyph's are.
pub fn glyph_outline(
    face: &owned_ttf_parser::Face<'_>,
    glyph: u16,
    m: CGAffineTransform,
    out: &mut Elements,
) {
    use crate::fonts::Segment;
    let p = |(x, y): (f32, f32)| (f64::from(x), f64::from(y));
    let mut pen: Option<(f32, f32)> = None;
    for segment in crate::fonts::outline(face, glyph) {
        let start = match segment {
            Segment::Line(a, _) | Segment::Quad(a, _, _) | Segment::Cubic(a, _, _, _) => a,
        };
        if pen != Some(start) {
            out.close();
            let (x, y) = p(start);
            out.move_to(m, x, y);
        }
        let end = match segment {
            Segment::Line(_, b) => {
                let (x, y) = p(b);
                out.line_to(m, x, y);
                b
            }
            Segment::Quad(_, c, b) => {
                let ((cx, cy), (x, y)) = (p(c), p(b));
                out.quad_to(m, cx, cy, x, y);
                b
            }
            Segment::Cubic(_, c1, c2, b) => {
                let ((ax, ay), (bx, by), (x, y)) = (p(c1), p(c2), p(b));
                out.cubic_to(m, ax, ay, bx, by, x, y);
                b
            }
        };
        pen = Some(end);
    }
    out.close();
}
