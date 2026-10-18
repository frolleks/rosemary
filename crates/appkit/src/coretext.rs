#![allow(non_snake_case)]

use std::ffi::c_void;
use std::sync::Arc;

use corefoundation::base::CFTypeRef;
use corefoundation::callbacks::Policy;
use corefoundation::collections::{self, Number};
use foundation::geometry::{NSPoint, NSRect, NSSize};

use crate::fonts::{self, FaceInfo, LoadedFace};

/// CoreText's keys, with the values Apple's CoreText gives them. A descriptor
/// key is the same string as its `NSFontDescriptor` counterpart, which is what
/// makes the two descriptor types interchangeable.
const ATTRIBUTE_GLOBALS: &[(&str, &str)] = &[
    ("_kCTFontFamilyNameKey", "CTFontFamilyName"),
    ("_kCTFontSubFamilyNameKey", "CTFontSubFamilyName"),
    ("_kCTFontStyleNameKey", "CTFontStyleName"),
    ("_kCTFontFullNameKey", "CTFontFullName"),
    ("_kCTFontDisplayNameAttribute", "NSFontVisibleNameAttribute"),
    ("_kCTFontFormatAttribute", "NSCTFontFormatAttribute"),
    ("_kCTFontVariationAttribute", "NSCTFontVariationAttribute"),
    ("_kCTFontWidthTrait", "NSCTFontProportionTrait"),
    (
        "_kCTFontVariationAxisIdentifierKey",
        "NSCTVariationAxisIdentifier",
    ),
    (
        "_kCTFontVariationAxisMinimumValueKey",
        "NSCTVariationAxisMinimumValue",
    ),
    (
        "_kCTFontVariationAxisMaximumValueKey",
        "NSCTVariationAxisMaximumValue",
    ),
    (
        "_kCTFontVariationAxisDefaultValueKey",
        "NSCTVariationAxisDefaultValue",
    ),
    ("_kCTFontVariationAxisNameKey", "NSCTVariationAxisName"),
    (
        "_kCTFontCollectionRemoveDuplicatesOption",
        "NSFontCollectionRemoveDuplicates",
    ),
    (
        "_kCTFontManagerRegisteredFontsChangedNotification",
        "CTFontManagerFontChangedNotification",
    ),
    ("_kCTFontCopyrightNameKey", "CTFontCopyrightName"),
    ("_kCTFontAttributeName", "NSFont"),
    (
        "_kCTFontCascadeListAttribute",
        "NSCTFontCascadeListAttribute",
    ),
    ("_kCTFontFamilyNameAttribute", "NSFontFamilyAttribute"),
    (
        "_kCTFontFeatureSelectorIdentifierKey",
        "CTFeatureSelectorIdentifier",
    ),
    (
        "_kCTFontFeatureSettingsAttribute",
        "NSCTFontFeatureSettingsAttribute",
    ),
    (
        "_kCTFontFeatureTypeIdentifierKey",
        "CTFeatureTypeIdentifier",
    ),
    ("_kCTFontLanguagesAttribute", "NSCTFontLanguagesAttribute"),
    ("_kCTFontNameAttribute", "NSFontNameAttribute"),
    ("_kCTFontPostScriptNameKey", "CTFontPostScriptName"),
    ("_kCTFontSizeAttribute", "NSFontSizeAttribute"),
    ("_kCTFontSlantTrait", "NSCTFontSlantTrait"),
    ("_kCTFontStyleNameAttribute", "NSFontFaceAttribute"),
    ("_kCTFontSymbolicTrait", "NSCTFontSymbolicTrait"),
    ("_kCTFontTraitsAttribute", "NSCTFontTraitsAttribute"),
    ("_kCTFontURLAttribute", "NSCTFontFileURLAttribute"),
    ("_kCTFontUniqueNameKey", "CTFontUniqueName"),
    ("_kCTFontWeightTrait", "NSCTFontWeightTrait"),
    ("_kCTForegroundColorAttributeName", "CTForegroundColor"),
    ("_kCTKernAttributeName", "NSKern"),
    ("_kCTLanguageAttributeName", "NSLanguage"),
    (
        "_kCTTypesetterOptionForcedEmbeddingLevel",
        "CTTypesetterOptionForcedEmbeddingLevel",
    ),
    ("_kCTVerticalFormsAttributeName", "CTVerticalForms"),
];

/// Where a resolved font's face lives. Private to this runtime, so a guest
/// copying attributes between descriptors carries them along unexamined.
const PATH_KEY: &str = "RosemaryFontFilePath";
const INDEX_KEY: &str = "RosemaryFontFileIndex";

/// A size CoreText uses for a font created with none.
const DEFAULT_SIZE: f64 = 12.0;

/// `kCTFontItalicTrait`, `kCTFontBoldTrait` and `kCTFontMonoSpaceTrait`.
const ITALIC_TRAIT: u32 = 1 << 0;
const BOLD_TRAIT: u32 = 1 << 1;
const MONOSPACE_TRAIT: u32 = 1 << 10;

fn key(text: &'static str) -> CFTypeRef {
    foundation::notification::name_object(text) as CFTypeRef
}

fn type_policy() -> Policy {
    Policy::from_type_callbacks()
}

fn new_dictionary(pairs: &[(CFTypeRef, CFTypeRef)]) -> CFTypeRef {
    collections::new_dictionary(pairs, Policy::from_key_callbacks(), type_policy(), false)
}

fn release(object: CFTypeRef) {
    if !object.is_null() {
        // SAFETY: a reference the caller owns.
        unsafe { corefoundation::api::CFRelease(object) };
    }
}

pub(crate) fn get(dictionary: CFTypeRef, name: &'static str) -> CFTypeRef {
    // SAFETY: null, or a dictionary a guest received from this runtime.
    match unsafe { collections::dictionary(dictionary) } {
        Some(_) => unsafe { corefoundation::api::CFDictionaryGetValue(dictionary, key(name)) },
        None => std::ptr::null(),
    }
}

fn get_string(dictionary: CFTypeRef, name: &'static str) -> Option<String> {
    let value = get(dictionary, name);
    if value.is_null() {
        return None;
    }
    // SAFETY: font attributes named as strings hold strings.
    let bytes = unsafe { foundation::string::bytes(value as _) };
    String::from_utf8(bytes).ok()
}

fn get_number(dictionary: CFTypeRef, name: &'static str) -> Option<f64> {
    let value = get(dictionary, name);
    // SAFETY: null or an object this runtime allocated.
    unsafe { collections::number(value) }.map(|number| number.as_f64())
}

fn string(text: &str) -> CFTypeRef {
    foundation::string::from_str(text) as CFTypeRef
}

/// CoreText's weight trait, from -1 to 1, as an OpenType weight class.
fn weight_class(weight: f64) -> u16 {
    const STOPS: [(f64, u16); 9] = [
        (-0.8, 100),
        (-0.6, 200),
        (-0.4, 300),
        (0.0, 400),
        (0.23, 500),
        (0.3, 600),
        (0.4, 700),
        (0.56, 800),
        (0.62, 900),
    ];
    STOPS
        .iter()
        .min_by(|a, b| (a.0 - weight).abs().total_cmp(&(b.0 - weight).abs()))
        .map_or(400, |stop| stop.1)
}

/// The inverse of [`weight_class`].
fn weight_trait(class: u16) -> f64 {
    match class {
        0..=150 => -0.8,
        151..=250 => -0.6,
        251..=350 => -0.4,
        351..=450 => 0.0,
        451..=550 => 0.23,
        551..=650 => 0.3,
        651..=750 => 0.4,
        751..=850 => 0.56,
        _ => 0.62,
    }
}

fn symbolic_traits(info: &FaceInfo) -> u32 {
    let mut traits = 0;
    if info.italic {
        traits |= ITALIC_TRAIT;
    }
    if info.weight >= 600 {
        traits |= BOLD_TRAIT;
    }
    if info.monospace {
        traits |= MONOSPACE_TRAIT;
    }
    traits
}

/// Language codes for the scripts a face has glyphs for, which is what Qt
/// decides a family's writing systems from.
fn languages(face: &LoadedFace) -> Vec<&'static str> {
    const SAMPLES: [(char, &str); 12] = [
        ('a', "en"),
        ('\u{0431}', "ru"),
        ('\u{03b1}', "el"),
        ('\u{05d0}', "he"),
        ('\u{0639}', "ar"),
        ('\u{0e01}', "th"),
        ('\u{0915}', "hi"),
        ('\u{4e2d}', "zh-Hans"),
        ('\u{7e41}', "zh-Hant"),
        ('\u{3042}', "ja"),
        ('\u{d55c}', "ko"),
        ('\u{1ea1}', "vi"),
    ];
    SAMPLES
        .iter()
        .filter(|(sample, _)| face.face().glyph_index(*sample).is_some())
        .map(|(_, language)| *language)
        .collect()
}

/// The attributes of `info` at `size`, as a font or descriptor.
fn face_attributes(info: &FaceInfo, size: f64) -> CFTypeRef {
    let mut owned = Vec::new();
    let mut own = |object: CFTypeRef| {
        owned.push(object);
        object
    };
    let weight = own(collections::new_number(Number::Float(weight_trait(
        info.weight,
    ))));
    let slant = own(collections::new_number(Number::Float(match info.italic {
        true => 0.07,
        false => 0.0,
    })));
    let symbolic = own(collections::new_number(Number::Integer(i64::from(
        symbolic_traits(info),
    ))));
    let traits = own(new_dictionary(&[
        (key("NSCTFontWeightTrait"), weight),
        (key("NSCTFontSlantTrait"), slant),
        (key("NSCTFontSymbolicTrait"), symbolic),
    ]));
    let postscript = match info.postscript.is_empty() {
        true => format!(
            "{}-{}",
            info.family.replace(' ', ""),
            info.style.replace(' ', "")
        ),
        false => info.postscript.clone(),
    };
    let language_list: Vec<CFTypeRef> = fonts::load(&info.path, info.index)
        .map(|face| languages(&face).into_iter().map(string).collect())
        .unwrap_or_default();
    let languages = own(collections::new_array(&language_list, type_policy(), false));
    for language in language_list {
        release(language);
    }
    let pairs = [
        (key("NSFontFamilyAttribute"), own(string(&info.family))),
        (key("NSFontFaceAttribute"), own(string(&info.style))),
        (key("NSFontNameAttribute"), own(string(&postscript))),
        (
            key("NSFontSizeAttribute"),
            own(collections::new_number(Number::Float(size))),
        ),
        (key("NSCTFontTraitsAttribute"), traits),
        (key("NSCTFontLanguagesAttribute"), languages),
        (
            key("NSCTFontFileURLAttribute"),
            own(corefoundation::url::new_file_url(&info.path, false)),
        ),
        (key(PATH_KEY), own(string(&info.path))),
        (
            key(INDEX_KEY),
            own(collections::new_number(Number::Integer(i64::from(
                info.index,
            )))),
        ),
    ];
    let font = new_dictionary(&pairs);
    for object in owned {
        release(object);
    }
    font
}

/// The face a descriptor names: its own file where it has been resolved, and
/// otherwise the best match for its family, weight and slant.
fn resolve(descriptor: CFTypeRef) -> Option<FaceInfo> {
    if let Some(path) = get_string(descriptor, PATH_KEY) {
        let index = get_number(descriptor, INDEX_KEY).unwrap_or(0.0) as u32;
        let family = get_string(descriptor, "NSFontFamilyAttribute").unwrap_or_default();
        let style = get_string(descriptor, "NSFontFaceAttribute").unwrap_or_default();
        if let Some(found) = fonts::all_faces()
            .into_iter()
            .find(|face| face.path == path && face.index == index)
        {
            return Some(found);
        }
        return Some(FaceInfo {
            family,
            style,
            postscript: String::new(),
            path,
            index,
            weight: 400,
            italic: false,
            monospace: false,
        });
    }
    let traits = get(descriptor, "NSCTFontTraitsAttribute");
    let weight = get_number(traits, "NSCTFontWeightTrait").map_or(400, weight_class);
    let symbolic = get_number(traits, "NSCTFontSymbolicTrait").unwrap_or(0.0) as u32;
    let slant = get_number(traits, "NSCTFontSlantTrait").unwrap_or(0.0);
    let weight = match symbolic & BOLD_TRAIT != 0 {
        true => weight.max(700),
        false => weight,
    };
    let italic = symbolic & ITALIC_TRAIT != 0 || slant > 0.0;
    let family = get_string(descriptor, "NSFontFamilyAttribute")
        .or_else(|| get_string(descriptor, "NSFontNameAttribute"))
        .unwrap_or_default();
    let style = get_string(descriptor, "NSFontFaceAttribute");
    if let Some(style) = style {
        if let Some(face) = fonts::all_faces().into_iter().find(|face| {
            face.family.eq_ignore_ascii_case(&family) && face.style.eq_ignore_ascii_case(&style)
        }) {
            return Some(face);
        }
    }
    fonts::resolve(&family, weight, italic)
}

/// A font for `descriptor` at `size`, keeping every attribute the descriptor
/// had that the face does not replace.
fn make_font(descriptor: CFTypeRef, size: f64) -> CFTypeRef {
    let size = match size > 0.0 {
        true => size,
        false => get_number(descriptor, "NSFontSizeAttribute")
            .filter(|size| *size > 0.0)
            .unwrap_or(DEFAULT_SIZE),
    };
    let Some(info) = resolve(descriptor) else {
        // No face at all: the descriptor with its size, so that the font
        // still answers its names.
        let size = collections::new_number(Number::Float(size));
        let overrides = new_dictionary(&[(key("NSFontSizeAttribute"), size)]);
        let font = merged_attributes(descriptor, overrides);
        release(overrides);
        release(size);
        return font;
    };
    let resolved = face_attributes(&info, size);
    let font = merged_attributes(descriptor, resolved);
    release(resolved);
    font
}

/// Copy `base`'s attributes with `overrides` layered on top.
fn merged_attributes(base: CFTypeRef, overrides: CFTypeRef) -> CFTypeRef {
    let mut pairs = Vec::new();
    for object in [base, overrides] {
        // SAFETY: null, or a dictionary a guest received from this runtime.
        if let Some(contents) = unsafe { collections::dictionary(object) } {
            pairs.extend(contents.entries.iter().copied());
        }
    }
    new_dictionary(&pairs)
}

fn loaded(font: CFTypeRef) -> Option<Arc<LoadedFace>> {
    let path = get_string(font, PATH_KEY)?;
    let index = get_number(font, INDEX_KEY).unwrap_or(0.0) as u32;
    fonts::load(&path, index)
}

fn font_size(font: CFTypeRef) -> f64 {
    get_number(font, "NSFontSizeAttribute").unwrap_or(0.0)
}

/// The face a font draws with and its size in points, for text AppKit draws
/// itself.
pub(crate) fn face_of(font: CFTypeRef) -> Option<(Arc<LoadedFace>, f64)> {
    if font.is_null() {
        return None;
    }
    Some((loaded(font)?, font_size(font)))
}

/// Points per font unit.
fn scale(font: CFTypeRef, face: &LoadedFace) -> f64 {
    font_size(font) / f64::from(face.face().units_per_em().max(1))
}

pub unsafe extern "C" fn CTFontCreateUIFontForLanguage(
    kind: u32,
    size: f64,
    _language: CFTypeRef,
) -> CFTypeRef {
    // `kCTFontUIFontUserFixedPitch` is 1; every other kind is proportional.
    let family = fonts::default_family(kind == 1).unwrap_or_else(|| "Sans".to_string());
    let name = string(&family);
    let descriptor = new_dictionary(&[(key("NSFontFamilyAttribute"), name)]);
    let font = make_font(descriptor, if size > 0.0 { size } else { 13.0 });
    release(descriptor);
    release(name);
    font
}

pub unsafe extern "C" fn CTFontCreateWithName(
    name: CFTypeRef,
    size: f64,
    _matrix: *const c_void,
) -> CFTypeRef {
    if name.is_null() {
        return std::ptr::null();
    }
    let descriptor = new_dictionary(&[
        (key("NSFontNameAttribute"), name),
        (key("NSFontFamilyAttribute"), name),
    ]);
    let font = make_font(descriptor, size);
    release(descriptor);
    font
}

pub unsafe extern "C" fn CTFontCopyFontDescriptor(font: CFTypeRef) -> CFTypeRef {
    if font.is_null() {
        return std::ptr::null();
    }
    unsafe { corefoundation::api::CFRetain(font) }
}

/// A font serves as its own graphics font.
pub unsafe extern "C" fn CTFontCopyGraphicsFont(
    font: CFTypeRef,
    attributes: *mut CFTypeRef,
) -> CFTypeRef {
    if font.is_null() {
        return std::ptr::null();
    }
    if !attributes.is_null() {
        // SAFETY: the caller supplied the documented optional output pointer.
        unsafe { *attributes = corefoundation::api::CFRetain(font) };
    }
    unsafe { corefoundation::api::CFRetain(font) }
}

fn copy_string_attribute(font: CFTypeRef, name: &'static str) -> CFTypeRef {
    let value = get(font, name);
    match value.is_null() {
        true => std::ptr::null(),
        // SAFETY: a live attribute value.
        false => unsafe { corefoundation::api::CFRetain(value) },
    }
}

pub unsafe extern "C" fn CTFontCopyName(font: CFTypeRef, name_key: CFTypeRef) -> CFTypeRef {
    let wanted = [
        ("CTFontFamilyName", "NSFontFamilyAttribute"),
        ("CTFontSubFamilyName", "NSFontFaceAttribute"),
        ("CTFontStyleName", "NSFontFaceAttribute"),
        ("CTFontPostScriptName", "NSFontNameAttribute"),
        ("CTFontUniqueName", "NSFontNameAttribute"),
        ("CTFontFullName", "NSFontNameAttribute"),
    ];
    for (name, attribute) in wanted {
        // SAFETY: both are strings, or `name_key` is null.
        if !name_key.is_null() && unsafe { corefoundation::api::CFEqual(name_key, key(name)) } != 0
        {
            return copy_string_attribute(font, attribute);
        }
    }
    std::ptr::null()
}

pub unsafe extern "C" fn CTFontCopyFamilyName(font: CFTypeRef) -> CFTypeRef {
    copy_string_attribute(font, "NSFontFamilyAttribute")
}

pub unsafe extern "C" fn CTFontCopyPostScriptName(font: CFTypeRef) -> CFTypeRef {
    copy_string_attribute(font, "NSFontNameAttribute")
}

pub unsafe extern "C" fn CTFontGetSymbolicTraits(font: CFTypeRef) -> u32 {
    let traits = get(font, "NSCTFontTraitsAttribute");
    get_number(traits, "NSCTFontSymbolicTrait").unwrap_or(0.0) as u32
}

pub unsafe extern "C" fn CTFontGetUnitsPerEm(font: CFTypeRef) -> u32 {
    loaded(font).map_or(1000, |face| u32::from(face.face().units_per_em()))
}

pub unsafe extern "C" fn CTFontGetSize(font: CFTypeRef) -> f64 {
    font_size(font)
}

fn metric(
    font: CFTypeRef,
    read: impl Fn(&owned_ttf_parser::Face<'_>) -> f64,
    fallback: f64,
) -> f64 {
    match loaded(font) {
        Some(face) => read(face.face()) * scale(font, &face),
        None => font_size(font) * fallback,
    }
}

pub unsafe extern "C" fn CTFontGetAscent(font: CFTypeRef) -> f64 {
    metric(font, |face| f64::from(face.ascender()), 0.8)
}

pub unsafe extern "C" fn CTFontGetDescent(font: CFTypeRef) -> f64 {
    metric(font, |face| -f64::from(face.descender()), 0.2)
}

pub unsafe extern "C" fn CTFontGetLeading(font: CFTypeRef) -> f64 {
    metric(font, |face| f64::from(face.line_gap()), 0.0)
}

pub unsafe extern "C" fn CTFontGetCapHeight(font: CFTypeRef) -> f64 {
    metric(
        font,
        |face| f64::from(face.capital_height().unwrap_or(face.ascender() * 7 / 10)),
        0.7,
    )
}

pub unsafe extern "C" fn CTFontGetXHeight(font: CFTypeRef) -> f64 {
    metric(
        font,
        |face| f64::from(face.x_height().unwrap_or(face.ascender() / 2)),
        0.5,
    )
}

pub unsafe extern "C" fn CTFontGetSlantAngle(font: CFTypeRef) -> f64 {
    loaded(font).map_or(0.0, |face| f64::from(face.face().italic_angle()))
}

pub unsafe extern "C" fn CTFontGetUnderlinePosition(font: CFTypeRef) -> f64 {
    metric(
        font,
        |face| f64::from(face.underline_metrics().map_or(-100, |m| m.position)),
        -0.1,
    )
}

pub unsafe extern "C" fn CTFontGetUnderlineThickness(font: CFTypeRef) -> f64 {
    metric(
        font,
        |face| f64::from(face.underline_metrics().map_or(50, |m| m.thickness)),
        0.05,
    )
}

fn rect(left: f64, bottom: f64, right: f64, top: f64) -> NSRect {
    NSRect {
        origin: NSPoint { x: left, y: bottom },
        size: NSSize {
            width: right - left,
            height: top - bottom,
        },
    }
}

pub unsafe extern "C" fn CTFontGetBoundingBox(font: CFTypeRef) -> NSRect {
    match loaded(font) {
        Some(face) => {
            let s = scale(font, &face);
            let b = face.face().global_bounding_box();
            rect(
                f64::from(b.x_min) * s,
                f64::from(b.y_min) * s,
                f64::from(b.x_max) * s,
                f64::from(b.y_max) * s,
            )
        }
        None => {
            let size = font_size(font);
            rect(0.0, size * -0.2, size * 0.6, size * 0.8)
        }
    }
}

pub unsafe extern "C" fn CTFontGetBoundingRectsForGlyphs(
    font: CFTypeRef,
    _orientation: u32,
    glyphs: *const u16,
    bounds: *mut NSRect,
    count: isize,
) -> NSRect {
    let count = count.max(0) as usize;
    let face = loaded(font);
    let mut union: Option<NSRect> = None;
    for at in 0..count {
        let glyph_rect = match (&face, glyphs.is_null()) {
            (Some(face), false) => {
                let s = scale(font, face);
                // SAFETY: the caller supplies `count` glyphs.
                let glyph = unsafe { *glyphs.add(at) };
                face.face()
                    .glyph_bounding_box(owned_ttf_parser::GlyphId(glyph))
                    .map_or(NSRect::default(), |b| {
                        rect(
                            f64::from(b.x_min) * s,
                            f64::from(b.y_min) * s,
                            f64::from(b.x_max) * s,
                            f64::from(b.y_max) * s,
                        )
                    })
            }
            _ => unsafe { CTFontGetBoundingBox(font) },
        };
        if !bounds.is_null() {
            // SAFETY: the caller supplies `count` writable rectangles.
            unsafe { bounds.add(at).write(glyph_rect) };
        }
        union = Some(match union {
            None => glyph_rect,
            Some(u) => rect(
                u.origin.x.min(glyph_rect.origin.x),
                u.origin.y.min(glyph_rect.origin.y),
                (u.origin.x + u.size.width).max(glyph_rect.origin.x + glyph_rect.size.width),
                (u.origin.y + u.size.height).max(glyph_rect.origin.y + glyph_rect.size.height),
            ),
        });
    }
    union.unwrap_or_default()
}

pub unsafe extern "C" fn CTFontGetAdvancesForGlyphs(
    font: CFTypeRef,
    _orientation: u32,
    glyphs: *const u16,
    advances: *mut NSSize,
    count: isize,
) -> f64 {
    let count = count.max(0) as usize;
    let face = loaded(font);
    let mut total = 0.0;
    for at in 0..count {
        let width = match (&face, glyphs.is_null()) {
            (Some(face), false) => {
                // SAFETY: the caller supplies `count` glyphs.
                let glyph = unsafe { *glyphs.add(at) };
                let units = face
                    .face()
                    .glyph_hor_advance(owned_ttf_parser::GlyphId(glyph))
                    .unwrap_or(0);
                f64::from(units) * scale(font, face)
            }
            _ => font_size(font) * 0.6,
        };
        if !advances.is_null() {
            // SAFETY: the caller supplies `count` writable advances.
            unsafe { advances.add(at).write(NSSize { width, height: 0.0 }) };
        }
        total += width;
    }
    total
}

/// Glyphs for UTF-16 characters: a surrogate pair's glyph goes at its first
/// unit and zero at its second, and the answer is whether every character
/// had one.
pub unsafe extern "C" fn CTFontGetGlyphsForCharacters(
    font: CFTypeRef,
    characters: *const u16,
    glyphs: *mut u16,
    count: isize,
) -> u8 {
    let Ok(count) = usize::try_from(count) else {
        return 0;
    };
    if count == 0 {
        return 1;
    }
    if characters.is_null() || glyphs.is_null() {
        return 0;
    }
    // SAFETY: the caller supplies `count` readable characters and writable glyphs.
    let (units, out) = unsafe {
        (
            std::slice::from_raw_parts(characters, count),
            std::slice::from_raw_parts_mut(glyphs, count),
        )
    };
    let Some(face) = loaded(font) else {
        out.copy_from_slice(units);
        return 1;
    };
    let mut complete = true;
    let mut at = 0;
    while at < count {
        let unit = units[at];
        let (character, width) = match (unit, units.get(at + 1)) {
            (0xd800..=0xdbff, Some(&low @ 0xdc00..=0xdfff)) => (
                char::from_u32(
                    0x10000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(low) - 0xdc00),
                ),
                2,
            ),
            _ => (char::from_u32(u32::from(unit)), 1),
        };
        let glyph = character
            .and_then(|character| face.face().glyph_index(character))
            .map_or(0, |glyph| glyph.0);
        complete &= glyph != 0;
        out[at] = glyph;
        if width == 2 {
            out[at + 1] = 0;
        }
        at += width;
    }
    u8::from(complete)
}

/// Rasterize glyphs into a bitmap context with its fill color.
///
/// A glyph's outline is scaled to the font's size, placed at its position,
/// and mapped through the context's text matrix and CTM, which is the whole
/// of CoreGraphics' text rendering model for a fill.
pub unsafe extern "C" fn CTFontDrawGlyphs(
    font: CFTypeRef,
    glyphs: *const u16,
    positions: *const NSPoint,
    count: usize,
    context: CFTypeRef,
) {
    let Some(face) = loaded(font) else {
        return;
    };
    let Some(device) = crate::cgcontext::text_to_device(context) else {
        return;
    };
    if glyphs.is_null() || positions.is_null() {
        return;
    }
    let s = scale(font, &face);
    for at in 0..count {
        // SAFETY: the caller supplies `count` glyphs and positions.
        let (glyph, position) = unsafe { (*glyphs.add(at), *positions.add(at)) };
        let segments = fonts::outline(face.face(), glyph);
        if segments.is_empty() {
            continue;
        }
        let map = |x: f32, y: f32| {
            let (dx, dy) =
                device.apply(f64::from(x) * s + position.x, f64::from(y) * s + position.y);
            (dx as f32, dy as f32)
        };
        if let Some((left, top, width, coverage)) = fonts::rasterize(&segments, map) {
            crate::cgcontext::fill_coverage(context, left, top, width, &coverage);
        }
    }
}

pub unsafe extern "C" fn CTFontCreatePathForGlyph(
    font: CFTypeRef,
    glyph: u16,
    transform: *const crate::cgcontext::CGAffineTransform,
) -> CFTypeRef {
    let mut bounds = NSRect::default();
    // SAFETY: one glyph and one rectangle.
    unsafe { CTFontGetBoundingRectsForGlyphs(font, 0, &glyph, &mut bounds, 1) };
    // SAFETY: a fresh path, with the caller's optional transform.
    unsafe {
        let path = crate::cgcontext::CGPathCreateMutable();
        crate::cgcontext::CGPathAddRect(path, transform, bounds);
        path
    }
}

pub unsafe extern "C" fn CTFontDescriptorCopyAttribute(
    descriptor: CFTypeRef,
    attribute: CFTypeRef,
) -> CFTypeRef {
    if descriptor.is_null() || attribute.is_null() {
        return std::ptr::null();
    }
    // SAFETY: null, or a dictionary a guest received from this runtime.
    if unsafe { collections::dictionary(descriptor) }.is_none() {
        return std::ptr::null();
    }
    let value = unsafe { corefoundation::api::CFDictionaryGetValue(descriptor, attribute) };
    if value.is_null() {
        value
    } else {
        unsafe { corefoundation::api::CFRetain(value) }
    }
}

pub unsafe extern "C" fn CTFontCopyAttribute(font: CFTypeRef, attribute: CFTypeRef) -> CFTypeRef {
    unsafe { CTFontDescriptorCopyAttribute(font, attribute) }
}

pub unsafe extern "C" fn CTFontCopyTraits(font: CFTypeRef) -> CFTypeRef {
    let traits = get(font, "NSCTFontTraitsAttribute");
    match traits.is_null() {
        true => new_dictionary(&[]),
        // SAFETY: a live attribute value.
        false => unsafe { corefoundation::api::CFRetain(traits) },
    }
}

/// `bool CGFontRenderingGetFontSmoothingDisabled(void)`: whether the user
/// turned off "Use font smoothing when available". They have not: that
/// setting (`AppleFontSmoothing`) is on until changed, and there is no pane
/// here to change it in.
#[expect(non_snake_case, reason = "the C spelling is the interface")]
pub extern "C" fn CGFontRenderingGetFontSmoothingDisabled() -> bool {
    false
}

/// An unresolved descriptor is its attributes.
pub unsafe extern "C" fn CTFontDescriptorCreateWithAttributes(attributes: CFTypeRef) -> CFTypeRef {
    if attributes.is_null() {
        return std::ptr::null();
    }
    unsafe { corefoundation::api::CFRetain(attributes) }
}

pub unsafe extern "C" fn CTFontDescriptorCreateMatchingFontDescriptor(
    descriptor: CFTypeRef,
    _mandatory_attributes: CFTypeRef,
) -> CFTypeRef {
    if descriptor.is_null() {
        return std::ptr::null();
    }
    let info = resolve(descriptor);
    match info {
        Some(info) => {
            let size = get_number(descriptor, "NSFontSizeAttribute").unwrap_or(0.0);
            let resolved = face_attributes(&info, size);
            let merged = merged_attributes(descriptor, resolved);
            release(resolved);
            merged
        }
        None => unsafe { corefoundation::api::CFRetain(descriptor) },
    }
}

/// Every face of the descriptor's family, which is how Qt populates a family;
/// null for a family no font has.
pub unsafe extern "C" fn CTFontDescriptorCreateMatchingFontDescriptors(
    descriptor: CFTypeRef,
    _mandatory_attributes: CFTypeRef,
) -> CFTypeRef {
    if descriptor.is_null() {
        return std::ptr::null();
    }
    if get(descriptor, PATH_KEY).is_null() {
        if let Some(family) = get_string(descriptor, "NSFontFamilyAttribute") {
            let style = get_string(descriptor, "NSFontFaceAttribute");
            let faces: Vec<CFTypeRef> = fonts::all_faces()
                .iter()
                .filter(|face| face.family.eq_ignore_ascii_case(&family))
                .filter(|face| {
                    style
                        .as_ref()
                        .is_none_or(|style| face.style.eq_ignore_ascii_case(style))
                })
                .map(|face| face_attributes(face, 0.0))
                .collect();
            if faces.is_empty() {
                return std::ptr::null();
            }
            let array = collections::new_array(&faces, type_policy(), false);
            faces.into_iter().for_each(release);
            return array;
        }
    }
    let matching =
        unsafe { CTFontDescriptorCreateMatchingFontDescriptor(descriptor, std::ptr::null()) };
    let array = collections::new_array(&[matching], type_policy(), false);
    release(matching);
    array
}

pub unsafe extern "C" fn CTFontDescriptorCreateCopyWithAttributes(
    original: CFTypeRef,
    attributes: CFTypeRef,
) -> CFTypeRef {
    if original.is_null() {
        return std::ptr::null();
    }
    merged_attributes(original, attributes)
}

pub unsafe extern "C" fn CTFontDescriptorCreateWithNameAndSize(
    name: CFTypeRef,
    size: f64,
) -> CFTypeRef {
    if name.is_null() {
        return std::ptr::null();
    }
    let size = collections::new_number(Number::Float(size));
    let descriptor = new_dictionary(&[
        (key("NSFontNameAttribute"), name),
        (key("NSFontSizeAttribute"), size),
    ]);
    release(size);
    descriptor
}

pub unsafe extern "C" fn CTFontCreateWithFontDescriptor(
    descriptor: CFTypeRef,
    size: f64,
    _matrix: *const c_void,
) -> CFTypeRef {
    if descriptor.is_null() {
        return std::ptr::null();
    }
    make_font(descriptor, size)
}

pub unsafe extern "C" fn CTFontCreateCopyWithAttributes(
    font: CFTypeRef,
    size: f64,
    _matrix: *const c_void,
    attributes: CFTypeRef,
) -> CFTypeRef {
    if font.is_null() {
        return std::ptr::null();
    }
    let merged = merged_attributes(font, attributes);
    let size = match size > 0.0 {
        true => size,
        false => font_size(font),
    };
    let result = make_font(merged, size);
    release(merged);
    result
}

/// A graphics font is the same attributes dictionary as its CTFont.
pub unsafe extern "C" fn CTFontCreateWithGraphicsFont(
    graphics_font: CFTypeRef,
    size: f64,
    _matrix: *const c_void,
    attributes: CFTypeRef,
) -> CFTypeRef {
    unsafe { CTFontCreateCopyWithAttributes(graphics_font, size, std::ptr::null(), attributes) }
}

/// kCTVersionNumber10_15.
pub unsafe extern "C" fn CTGetCoreTextVersion() -> u32 {
    0x000C_0000
}

/// The raw bytes of one of the face's tables, which Qt's HarfBuzz shapes with.
pub unsafe extern "C" fn CTFontCopyTable(font: CFTypeRef, table: u32, _options: u32) -> CFTypeRef {
    let Some(face) = loaded(font) else {
        return std::ptr::null();
    };
    let tag = owned_ttf_parser::Tag::from_bytes(&table.to_be_bytes());
    match face.face().raw_face().table(tag) {
        Some(bytes) => collections::new_data(bytes.to_vec()),
        None => std::ptr::null(),
    }
}

/// Fallback families after the default one, for characters it lacks.
pub unsafe extern "C" fn CTFontCopyDefaultCascadeListForLanguages(
    _font: CFTypeRef,
    _languages: CFTypeRef,
) -> CFTypeRef {
    let mut families: Vec<String> = fonts::default_family(false).into_iter().collect();
    for wanted in [
        "Noto Sans CJK SC",
        "Noto Sans",
        "DejaVu Sans",
        "Noto Color Emoji",
    ] {
        if fonts::all_faces().iter().any(|face| face.family == wanted)
            && !families.iter().any(|family| family == wanted)
        {
            families.push(wanted.to_string());
        }
    }
    let descriptors: Vec<CFTypeRef> = families
        .iter()
        .map(|family| {
            let name = string(family);
            let descriptor = new_dictionary(&[(key("NSFontFamilyAttribute"), name)]);
            release(name);
            descriptor
        })
        .collect();
    let array = collections::new_array(&descriptors, type_policy(), false);
    descriptors.into_iter().for_each(release);
    array
}

pub unsafe extern "C" fn CTFontManagerCopyAvailableFontFamilyNames() -> CFTypeRef {
    let mut families: Vec<String> = fonts::all_faces()
        .into_iter()
        .map(|face| face.family)
        .collect();
    families.sort();
    families.dedup();
    let names: Vec<CFTypeRef> = families.iter().map(|family| string(family)).collect();
    let array = collections::new_array(&names, type_policy(), false);
    names.into_iter().for_each(release);
    array
}

fn descriptors_for(faces: &[FaceInfo]) -> CFTypeRef {
    if faces.is_empty() {
        return std::ptr::null();
    }
    let descriptors: Vec<CFTypeRef> = faces
        .iter()
        .map(|face| face_attributes(face, 0.0))
        .collect();
    let array = collections::new_array(&descriptors, type_policy(), false);
    descriptors.into_iter().for_each(release);
    array
}

/// Register the faces in a font file and describe them.
pub unsafe extern "C" fn CTFontManagerCreateFontDescriptorsFromURL(url: CFTypeRef) -> CFTypeRef {
    let Some(path) = (unsafe { corefoundation::url::as_url(url) }).and_then(|url| url.file_path())
    else {
        return std::ptr::null();
    };
    // Translated once, here: `register_file` keeps the path in each `FaceInfo`
    // and `fonts::load` reads it again later.
    let path = prefix::ns::host_path(&path);
    descriptors_for(&fonts::register_file(&path.to_string_lossy()))
}

/// Font bytes in memory, written to a file of their own so that they load
/// like every other face: one file per distinct content.
fn font_file(bytes: &[u8]) -> Option<String> {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    let directory = std::env::temp_dir().join("rosemary-fonts");
    let _ = std::fs::create_dir_all(&directory);
    let path = directory.join(format!("{:016x}.ttf", hasher.finish()));
    if !path.exists() && std::fs::write(&path, bytes).is_err() {
        return None;
    }
    Some(path.to_string_lossy().into_owned())
}

/// As [`CTFontManagerCreateFontDescriptorsFromURL`], for font bytes in memory.
pub unsafe extern "C" fn CTFontManagerCreateFontDescriptorFromData(data: CFTypeRef) -> CFTypeRef {
    // SAFETY: null or an object this runtime allocated.
    let Some(bytes) = (unsafe { collections::data(data) }) else {
        return std::ptr::null();
    };
    let Some(path) = font_file(bytes.as_slice()) else {
        return std::ptr::null();
    };
    let faces = fonts::register_file(&path);
    let Some(first) = faces.first() else {
        return std::ptr::null();
    };
    face_attributes(first, 0.0)
}

/// `CGFontRef CGFontCreateWithDataProvider(CGDataProviderRef provider)`: the
/// first face in the font data a provider holds, or null for data that is not
/// a font.
///
/// A graphics font is the same attributes dictionary as its CTFont (see
/// [`CTFontCreateWithGraphicsFont`]). It is not registered: as on a Mac, a
/// font made this way draws, and becomes one a lookup by name finds only once
/// [`CTFontManagerRegisterGraphicsFont`] registers it.
pub unsafe extern "C" fn CGFontCreateWithDataProvider(provider: CFTypeRef) -> CFTypeRef {
    let Some(path) = crate::graphics::provider_bytes(provider).and_then(font_file) else {
        return std::ptr::null();
    };
    match fonts::describe_file(&path).first() {
        Some(face) => face_attributes(face, 0.0),
        None => std::ptr::null(),
    }
}

/// `void CGFontRelease(CGFontRef font)`: `CFRelease`, except that a null font
/// is no error.
pub unsafe extern "C" fn CGFontRelease(font: CFTypeRef) {
    if !font.is_null() {
        release(font);
    }
}

/// `kCTFontManagerErrorDomain`
const FONT_MANAGER_ERROR_DOMAIN: &str = "com.apple.CoreText.CTFontManagerErrorDomain";
/// `kCTFontManagerErrorInvalidFontData`
const INVALID_FONT_DATA: i64 = 104;
/// `kCTFontManagerErrorAlreadyRegistered`
const ALREADY_REGISTERED: i64 = 105;
/// `kCTFontManagerErrorNotRegistered`
const NOT_REGISTERED: i64 = 201;

/// The face a graphics font draws with, read from its file.
fn graphics_face(font: CFTypeRef) -> Option<FaceInfo> {
    if font.is_null() {
        return None;
    }
    let path = get_string(font, PATH_KEY)?;
    let index = get_number(font, INDEX_KEY).unwrap_or(0.0) as u32;
    fonts::describe_file(&path)
        .into_iter()
        .find(|face| face.index == index)
}

/// A font manager error, stored where the caller asked for one, which owns it.
fn font_manager_error(error: *mut CFTypeRef, code: i64, description: &str) {
    if error.is_null() {
        return;
    }
    let made = foundation::error::make(FONT_MANAGER_ERROR_DOMAIN, code, description);
    // SAFETY: the caller's optional out-pointer; a `CFErrorRef *` result is
    // the caller's to release, and `make`'s is autoreleased.
    unsafe { *error = objc::arc::retain(made) as CFTypeRef };
}

/// `bool CTFontManagerRegisterGraphicsFont(CGFontRef font, CFErrorRef *error)`:
/// make a graphics font available to this process by name. A font whose
/// PostScript name is registered already is refused with
/// `kCTFontManagerErrorAlreadyRegistered`, as Apple's is.
pub unsafe extern "C" fn CTFontManagerRegisterGraphicsFont(
    font: CFTypeRef,
    error: *mut CFTypeRef,
) -> bool {
    let Some(face) = graphics_face(font) else {
        font_manager_error(
            error,
            INVALID_FONT_DATA,
            "The file does not contain valid font data.",
        );
        return false;
    };
    if !fonts::register(&face) {
        font_manager_error(
            error,
            ALREADY_REGISTERED,
            &format!(
                "The font {:?} has already been registered in the specified scope.",
                face.postscript
            ),
        );
        return false;
    }
    true
}

/// `bool CTFontManagerUnregisterGraphicsFont(CGFontRef font, CFErrorRef *error)`:
/// withdraw what [`CTFontManagerRegisterGraphicsFont`] registered, and refuse
/// a font that is not registered with `kCTFontManagerErrorNotRegistered`.
pub unsafe extern "C" fn CTFontManagerUnregisterGraphicsFont(
    font: CFTypeRef,
    error: *mut CFTypeRef,
) -> bool {
    let Some(face) = graphics_face(font) else {
        font_manager_error(
            error,
            INVALID_FONT_DATA,
            "The file does not contain valid font data.",
        );
        return false;
    };
    if !fonts::unregister(&face) {
        font_manager_error(
            error,
            NOT_REGISTERED,
            &format!(
                "The font {:?} is not registered in the specified scope.",
                face.postscript
            ),
        );
        return false;
    }
    true
}

/// `CFIndex CTFontGetGlyphCount(CTFontRef)`: the face's `maxp` glyph count, or
/// zero for a font with no face behind it.
pub unsafe extern "C" fn CTFontGetGlyphCount(font: CFTypeRef) -> isize {
    loaded(font).map_or(0, |face| face.face().number_of_glyphs() as isize)
}

/// `CFArrayRef CTFontCopyAvailableTables(CTFontRef, CTFontTableOptions)`: the
/// tags of the face's tables, in its table directory's order. Each value is
/// the tag itself rather than an object, as Apple's array holds them, so the
/// array retains nothing.
pub unsafe extern "C" fn CTFontCopyAvailableTables(font: CFTypeRef, _options: u32) -> CFTypeRef {
    let Some(face) = loaded(font) else {
        return std::ptr::null();
    };
    let tags: Vec<CFTypeRef> = face
        .face()
        .raw_face()
        .table_records
        .into_iter()
        .map(|record| u32::from_be_bytes(record.tag.to_bytes()) as usize as CFTypeRef)
        .collect();
    collections::new_array(&tags, Policy::NONE, false)
}

/// A `CTFontCollection`: the query descriptors it was made from, or every
/// available face.
#[repr(C)]
struct Collection {
    isa: *const c_void,
    /// An array this collection owns, or null for every available face.
    query: CFTypeRef,
}

fn collection_class() -> &'static objc::class::Class {
    static CLASS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let class = *CLASS.get_or_init(|| {
        let class = corefoundation::base::register(
            c"CTFontCollection",
            None,
            size_of::<Collection>(),
            true,
        );
        class.replace_method(
            objc::sel::get("dealloc"),
            collection_dealloc as *const c_void,
            c"v16@0:8",
        );
        objc::class::ptr(class) as usize
    });
    // SAFETY: a leaked class registered above.
    unsafe { &*(class as *const objc::class::Class) }
}

unsafe extern "C" fn collection_dealloc(receiver: objc::object::Id, _sel: objc::sel::Sel) {
    // SAFETY: `-dealloc` of a collection, whose body is `Collection`.
    release(unsafe { (*(receiver as *const Collection)).query });
    objc::arc::finalize(receiver);
}

/// A new collection owning `query`, a reference of its own or null.
fn make_collection(query: CFTypeRef) -> CFTypeRef {
    // SAFETY: `Collection` is the registered layout.
    let collection = unsafe { corefoundation::base::allocate::<Collection>(collection_class()) };
    // SAFETY: a fresh allocation whose query is written once here.
    unsafe { (*collection).query = query };
    collection as CFTypeRef
}

fn collection_of<'a>(collection: CFTypeRef) -> Option<&'a Collection> {
    // SAFETY: null or an object a guest received from this runtime.
    let is_collection = !collection.is_null()
        && unsafe { corefoundation::base::is_kind_of(collection, collection_class()) };
    // SAFETY: checked to be a collection.
    is_collection.then(|| unsafe { &*(collection as *const Collection) })
}

/// The elements of a CF array a caller passed.
fn array_values(array: CFTypeRef) -> Vec<CFTypeRef> {
    if array.is_null() {
        return Vec::new();
    }
    // SAFETY: an array the caller passed, read by index within its count.
    unsafe {
        let count = corefoundation::api::CFArrayGetCount(array);
        (0..count)
            .map(|at| corefoundation::api::CFArrayGetValueAtIndex(array, at))
            .collect()
    }
}

/// `CTFontCollectionRef CTFontCollectionCreateFromAvailableFonts(CFDictionaryRef
/// options)`: every face this process can use.
///
/// The one option, removing duplicates, is asked for with
/// `kCTFontCollectionRemoveDuplicatesOption`, which this tree does not
/// publish, so no options dictionary here can carry it.
pub unsafe extern "C" fn CTFontCollectionCreateFromAvailableFonts(
    _options: CFTypeRef,
) -> CFTypeRef {
    make_collection(std::ptr::null())
}

/// `CTFontCollectionRef CTFontCollectionCreateWithFontDescriptors(CFArrayRef
/// queryDescriptors, CFDictionaryRef options)`: what those descriptors match.
/// A null array matches nothing.
pub unsafe extern "C" fn CTFontCollectionCreateWithFontDescriptors(
    query: CFTypeRef,
    _options: CFTypeRef,
) -> CFTypeRef {
    let values = array_values(query);
    make_collection(collections::new_array(&values, type_policy(), false))
}

/// `CFTypeID CTFontCollectionGetTypeID(void)`.
pub unsafe extern "C" fn CTFontCollectionGetTypeID() -> corefoundation::base::CFTypeID {
    corefoundation::base::type_id(collection_class())
}

/// `CFArrayRef CTFontCollectionCreateMatchingFontDescriptors(CTFontCollectionRef)`:
/// a descriptor per matching face, or null when nothing matches.
pub unsafe extern "C" fn CTFontCollectionCreateMatchingFontDescriptors(
    collection: CFTypeRef,
) -> CFTypeRef {
    let Some(collection) = collection_of(collection) else {
        return std::ptr::null();
    };
    if collection.query.is_null() {
        return descriptors_for(&fonts::all_faces());
    }
    let mut matched: Vec<CFTypeRef> = Vec::new();
    for query in array_values(collection.query) {
        // SAFETY: a descriptor the collection was made with.
        let found =
            unsafe { CTFontDescriptorCreateMatchingFontDescriptors(query, std::ptr::null()) };
        for descriptor in array_values(found) {
            let path = get_string(descriptor, PATH_KEY);
            let index = get_number(descriptor, INDEX_KEY);
            // One face matched by two queries is in the result once.
            let seen = path.is_some()
                && matched.iter().any(|other| {
                    get_string(*other, PATH_KEY) == path && get_number(*other, INDEX_KEY) == index
                });
            if !seen {
                // SAFETY: a live descriptor, kept by the result.
                matched.push(unsafe { corefoundation::api::CFRetain(descriptor) });
            }
        }
        release(found);
    }
    if matched.is_empty() {
        return std::ptr::null();
    }
    let array = collections::new_array(&matched, type_policy(), false);
    matched.into_iter().for_each(release);
    array
}

exports::exports! {
    functions {
        "CTFontGetGlyphCount" => CTFontGetGlyphCount,
        "CTFontCopyAvailableTables" => CTFontCopyAvailableTables,
        "CTFontCollectionCreateFromAvailableFonts" => CTFontCollectionCreateFromAvailableFonts,
        "CTFontCollectionCreateWithFontDescriptors" => CTFontCollectionCreateWithFontDescriptors,
        "CTFontCollectionGetTypeID" => CTFontCollectionGetTypeID,
        "CTFontCollectionCreateMatchingFontDescriptors"
            => CTFontCollectionCreateMatchingFontDescriptors,
        "CTFontCreateUIFontForLanguage" => CTFontCreateUIFontForLanguage,
        "CTFontCreateWithName" => CTFontCreateWithName,
        "CTFontCopyFontDescriptor" => CTFontCopyFontDescriptor,
        "CTFontCopyGraphicsFont" => CTFontCopyGraphicsFont,
        "CTFontCopyName" => CTFontCopyName,
        "CTFontCopyFamilyName" => CTFontCopyFamilyName,
        "CTFontCopyPostScriptName" => CTFontCopyPostScriptName,
        "CTFontGetSymbolicTraits" => CTFontGetSymbolicTraits,
        "CTFontGetUnitsPerEm" => CTFontGetUnitsPerEm,
        "CTFontGetSize" => CTFontGetSize,
        "CTFontGetAscent" => CTFontGetAscent,
        "CTFontGetDescent" => CTFontGetDescent,
        "CTFontGetLeading" => CTFontGetLeading,
        "CTFontGetCapHeight" => CTFontGetCapHeight,
        "CTFontGetXHeight" => CTFontGetXHeight,
        "CTFontGetSlantAngle" => CTFontGetSlantAngle,
        "CTFontGetUnderlinePosition" => CTFontGetUnderlinePosition,
        "CTFontGetUnderlineThickness" => CTFontGetUnderlineThickness,
        "CTFontGetBoundingBox" => CTFontGetBoundingBox,
        "CTFontGetBoundingRectsForGlyphs" => CTFontGetBoundingRectsForGlyphs,
        "CTFontGetAdvancesForGlyphs" => CTFontGetAdvancesForGlyphs,
        "CTFontGetGlyphsForCharacters" => CTFontGetGlyphsForCharacters,
        "CTFontDrawGlyphs" => CTFontDrawGlyphs,
        "CTFontCreatePathForGlyph" => CTFontCreatePathForGlyph,
        "CTFontDescriptorCopyAttribute" => CTFontDescriptorCopyAttribute,
        "CTFontCopyAttribute" => CTFontCopyAttribute,
        "CTFontCopyTraits" => CTFontCopyTraits,
        "CTFontDescriptorCreateWithAttributes" => CTFontDescriptorCreateWithAttributes,
        "CTFontDescriptorCreateMatchingFontDescriptor" => CTFontDescriptorCreateMatchingFontDescriptor,
        "CTFontCreateWithFontDescriptor" => CTFontCreateWithFontDescriptor,
        "CTFontCopyTable" => CTFontCopyTable,
        "CTFontCopyDefaultCascadeListForLanguages" => CTFontCopyDefaultCascadeListForLanguages,
        "CTFontManagerCopyAvailableFontFamilyNames" => CTFontManagerCopyAvailableFontFamilyNames,
        "CTFontManagerCreateFontDescriptorsFromURL" => CTFontManagerCreateFontDescriptorsFromURL,
        "CTFontManagerCreateFontDescriptorFromData" => CTFontManagerCreateFontDescriptorFromData,
        "CTFontManagerRegisterGraphicsFont" => CTFontManagerRegisterGraphicsFont,
        "CTFontManagerUnregisterGraphicsFont" => CTFontManagerUnregisterGraphicsFont,
        "CGFontCreateWithDataProvider" => CGFontCreateWithDataProvider,
        "CGFontRelease" => CGFontRelease,
        "CTFontDescriptorCreateCopyWithAttributes" => CTFontDescriptorCreateCopyWithAttributes,
        "CTFontDescriptorCreateWithNameAndSize" => CTFontDescriptorCreateWithNameAndSize,
        "CTFontDescriptorCreateMatchingFontDescriptors" => CTFontDescriptorCreateMatchingFontDescriptors,
        "CTFontCreateCopyWithAttributes" => CTFontCreateCopyWithAttributes,
        "CTFontCreateWithGraphicsFont" => CTFontCreateWithGraphicsFont,
        "CTGetCoreTextVersion" => CTGetCoreTextVersion,
    }
}

pub fn data_symbols() -> Vec<(String, u64)> {
    corefoundation::base::string_globals(ATTRIBUTE_GLOBALS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The host's default sans-serif font, or `None` on a host with no
    /// fontconfig, where these tests have nothing to read.
    fn default_font(size: f64) -> Option<CFTypeRef> {
        crate::bootstrap();
        fonts::default_family(false)?;
        // SAFETY: a null language is documented.
        let font = unsafe { CTFontCreateUIFontForLanguage(0, size, std::ptr::null()) };
        loaded(font).is_some().then_some(font)
    }

    /// The glyph count and table list are the face's own, the tags held as
    /// plain values.
    #[test]
    fn a_font_lists_its_tables_and_counts_its_glyphs() {
        let Some(font) = default_font(12.0) else {
            return;
        };
        // SAFETY: a live font, and an array of tags read within its count.
        unsafe {
            let face = loaded(font).unwrap();
            assert_eq!(
                CTFontGetGlyphCount(font),
                face.face().number_of_glyphs() as isize
            );
            assert!(CTFontGetGlyphCount(font) > 0);
            let tables = CTFontCopyAvailableTables(font, 0);
            let tags: Vec<u32> = array_values(tables)
                .into_iter()
                .map(|t| t as usize as u32)
                .collect();
            for tag in [*b"head", *b"cmap", *b"maxp"] {
                assert!(
                    tags.contains(&u32::from_be_bytes(tag)),
                    "{:?} listed",
                    std::str::from_utf8(&tag)
                );
            }
            release(tables);
            release(font);
        }
    }

    /// Every face is in the collection of available fonts, and a collection
    /// of queries holds what they match, each face once.
    #[test]
    fn a_collection_matches_the_available_faces_or_its_queries() {
        crate::bootstrap();
        let faces = fonts::all_faces();
        let Some(first) = faces.first() else {
            return;
        };
        // SAFETY: collections made and released here.
        unsafe {
            let all = CTFontCollectionCreateFromAvailableFonts(std::ptr::null());
            assert_eq!(
                corefoundation::api::CFGetTypeID(all),
                CTFontCollectionGetTypeID()
            );
            let every = CTFontCollectionCreateMatchingFontDescriptors(all);
            assert_eq!(array_values(every).len(), faces.len());

            let family = string(&first.family);
            let query = new_dictionary(&[(key("NSFontFamilyAttribute"), family)]);
            let queries = collections::new_array(&[query, query], type_policy(), false);
            let some = CTFontCollectionCreateWithFontDescriptors(queries, std::ptr::null());
            let matched = CTFontCollectionCreateMatchingFontDescriptors(some);
            let in_family = faces
                .iter()
                .filter(|f| f.family.eq_ignore_ascii_case(&first.family))
                .count();
            assert_eq!(
                array_values(matched).len(),
                in_family,
                "the same query twice adds nothing"
            );

            let none =
                CTFontCollectionCreateWithFontDescriptors(std::ptr::null(), std::ptr::null());
            assert!(CTFontCollectionCreateMatchingFontDescriptors(none).is_null());
            for object in [all, every, family, query, queries, some, matched, none] {
                release(object);
            }
        }
    }

    #[test]
    fn weight_traits_round_trip_through_weight_classes() {
        for class in [100, 300, 400, 500, 600, 700, 900] {
            assert_eq!(weight_class(weight_trait(class)), class);
        }
    }

    #[test]
    fn a_font_reads_its_metrics_from_its_face() {
        let Some(font) = default_font(20.0) else {
            return;
        };
        // SAFETY: a live font.
        unsafe {
            assert_eq!(CTFontGetSize(font), 20.0);
            let ascent = CTFontGetAscent(font);
            let descent = CTFontGetDescent(font);
            assert!(ascent > 10.0 && ascent < 30.0, "ascent {ascent}");
            assert!(descent > 0.0 && descent < 10.0, "descent {descent}");
            let head = CTFontCopyTable(font, u32::from_be_bytes(*b"head"), 0);
            assert!(!head.is_null());
            release(head);
            release(font);
        }
    }

    #[test]
    fn glyphs_for_characters_come_from_the_cmap_and_draw_into_a_context() {
        let Some(font) = default_font(24.0) else {
            return;
        };
        let characters = [b'H' as u16];
        let mut glyph = [0u16];
        let mut pixels = vec![0u8; 32 * 32];
        // SAFETY: the arrays hold the counts passed; the context wraps `pixels`.
        unsafe {
            assert_eq!(
                CTFontGetGlyphsForCharacters(font, characters.as_ptr(), glyph.as_mut_ptr(), 1),
                1
            );
            assert_ne!(glyph[0], u16::from(b'H'));
            let mut advance = NSSize::default();
            CTFontGetAdvancesForGlyphs(font, 0, glyph.as_ptr(), &mut advance, 1);
            assert!(advance.width > 5.0);
            let context = crate::cgcontext::CGBitmapContextCreate(
                pixels.as_mut_ptr().cast(),
                32,
                32,
                8,
                32,
                std::ptr::null(),
                7,
            );
            crate::cgcontext::CGContextSetGrayFillColor(context, 1.0, 1.0);
            let origin = NSPoint { x: 4.0, y: 6.0 };
            CTFontDrawGlyphs(font, glyph.as_ptr(), &origin, 1, context);
            release(context);
            release(font);
        }
        let covered = pixels.iter().filter(|&&value| value > 128).count();
        assert!(covered > 20, "only {covered} pixels covered");
    }

    #[test]
    fn descriptor_copy_overrides_original_attributes() {
        crate::bootstrap();
        let name = string("Fira Mono");
        // SAFETY: all arguments are live Core Foundation objects.
        unsafe {
            let original = CTFontDescriptorCreateWithNameAndSize(name, 12.0);
            let size = collections::new_number(Number::Float(20.0));
            let overrides = new_dictionary(&[(key("NSFontSizeAttribute"), size)]);
            let copy = CTFontDescriptorCreateCopyWithAttributes(original, overrides);
            assert_eq!(CTFontGetSize(copy), 20.0);
            assert_eq!(CTFontGetSize(original), 12.0);
            for object in [copy, overrides, size, original, name] {
                release(object);
            }
        }
    }
}
