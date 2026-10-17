use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use foundation::unarchiver::{Archive, Uid};
use objc::object::Id;

use crate::define::{class_methods, methods};

/// `-[NSBundle loadNibNamed:owner:topLevelObjects:]` is an AppKit category on
/// Foundation's bundle class.
unsafe extern "C" fn load_named(
    bundle: Id,
    _sel: objc::sel::Sel,
    name: Id,
    owner: Id,
    top_level: *mut Id,
) -> u8 {
    if !top_level.is_null() {
        // SAFETY: the caller passed a writable `NSArray **`.
        unsafe { *top_level = std::ptr::null_mut() };
    }
    // SAFETY: the name is an NSString or nil.
    let Ok(name) = String::from_utf8(unsafe { foundation::string::bytes(name) }) else {
        return 0;
    };
    let path = unsafe { foundation::bundle::resource_for_object(bundle, &name, "nib") }
        .or_else(|| unsafe { foundation::bundle::resource_for_object(bundle, &name, "") });
    let Some(path) = path else {
        return 0;
    };
    let loaded = match load(&path, owner) {
        Ok(loaded) => loaded,
        Err(why) => {
            eprintln!("rosemary: appkit: {}: {why}", path.display());
            return 0;
        }
    };
    loaded.report(&path);
    if !top_level.is_null() {
        // SAFETY: the caller's writable output slot.
        unsafe { *top_level = top_level_array(&loaded, owner) };
    }
    1
}

/// The objects a load built, less File's Owner, as an autoreleased `NSArray`:
/// what `topLevelObjects:` hands back.
fn top_level_array(loaded: &Loaded, owner: Id) -> Id {
    let objects: Vec<_> = loaded
        .objects
        .values()
        .filter(|object| !object.is_null() && **object != owner)
        .map(|object| *object as corefoundation::base::CFTypeRef)
        .collect();
    let array = corefoundation::collections::new_array(
        &objects,
        corefoundation::callbacks::Policy::from_type_callbacks(),
        false,
    );
    // SAFETY: a fresh array.
    unsafe { corefoundation::api::CFAutorelease(array) as Id }
}

/// `+[NSBundle loadNibNamed:owner:]`, the pre-10.8 spelling. It searches the
/// bundle of the owner's class. The top-level objects stay retained for the owner to release, which
/// is what the old API promised and what [`load`] already does.
unsafe extern "C" fn load_named_class(class: Id, _sel: objc::sel::Sel, name: Id, owner: Id) -> u8 {
    // SAFETY: `+bundleForClass:` is `id (Class, SEL, Class)`, and the owner is
    // an object or nil.
    let bundle = unsafe {
        let owner_class = objc::object::class_of(owner)
            .map_or(std::ptr::null_mut(), |c| objc::class::ptr(c) as Id);
        let f: unsafe extern "C" fn(Id, objc::sel::Sel, Id) -> Id =
            std::mem::transmute(objc::msg::entry());
        f(class, objc::sel::get("bundleForClass:"), owner_class)
    };
    // SAFETY: the same arguments, with no top-level array asked for.
    unsafe { load_named(bundle, _sel, name, owner, std::ptr::null_mut()) }
}

/// An `NSNib`: a nib read into memory once, to be instantiated any number of
/// times.
///
/// The archive is kept as bytes rather than parsed, because each
/// `-instantiateWithOwner:topLevelObjects:` builds a fresh object graph from it
/// and a parsed archive is only the first step of that.
#[repr(C)]
pub struct Nib {
    isa: *const std::ffi::c_void,
    /// The archive, from `Box::into_raw`; null until an initializer succeeds.
    bytes: *mut Vec<u8>,
    /// The bundle the nib's resources are looked up in, retained.
    bundle: Id,
    /// Where the archive came from, for reporting; from `Box::into_raw`, or null
    /// for a nib made from data.
    path: *mut std::path::PathBuf,
}

pub const NIB_INSTANCE_SIZE: usize = size_of::<Nib>();

fn nib_of<'a>(receiver: Id) -> &'a mut Nib {
    // SAFETY: an `NSNib`, which `classes` declared with room for a `Nib`.
    unsafe { &mut *(receiver as *mut Nib) }
}

/// `+[NSBundle mainBundle]`, the bundle a nil `bundle:` argument means.
fn main_bundle() -> Id {
    let Some(class) = objc::class::lookup(c"NSBundle") else {
        return std::ptr::null_mut();
    };
    // SAFETY: `+mainBundle` is `id (Class, SEL)`.
    unsafe {
        let f: unsafe extern "C" fn(Id, objc::sel::Sel) -> Id =
            std::mem::transmute(objc::msg::entry());
        f(objc::class::ptr(class) as Id, objc::sel::get("mainBundle"))
    }
}

/// Give `receiver` its archive and bundle, or release it and answer nil, as an
/// initializer that fails does.
fn initialized(receiver: Id, bytes: Option<Vec<u8>>, bundle: Id, path: Option<PathBuf>) -> Id {
    let Some(bytes) = bytes else {
        objc::arc::release(receiver);
        return std::ptr::null_mut();
    };
    let nib = nib_of(receiver);
    nib.bytes = Box::into_raw(Box::new(bytes));
    nib.bundle = objc::arc::retain(bundle);
    nib.path = path.map_or(std::ptr::null_mut(), |p| Box::into_raw(Box::new(p)));
    receiver
}

/// `-[NSNib initWithNibNamed:bundle:]`.
///
/// `name` is the nib's name with or without its `.nib` extension; a nil
/// `bundle` is the main bundle. A nib that cannot be found is nil, as Apple
/// documents, rather than an exception.
unsafe extern "C" fn init_with_nib_named(
    receiver: Id,
    _sel: objc::sel::Sel,
    name: Id,
    bundle: Id,
) -> Id {
    let bundle = match bundle.is_null() {
        true => main_bundle(),
        false => bundle,
    };
    // SAFETY: the name is an NSString or nil.
    let name = String::from_utf8(unsafe { foundation::string::bytes(name) }).unwrap_or_default();
    let name = name.strip_suffix(".nib").unwrap_or(&name);
    let path = match name.is_empty() || bundle.is_null() {
        true => None,
        // SAFETY: an `NSBundle`.
        false => unsafe { foundation::bundle::resource_for_object(bundle, name, "nib") },
    };
    let bytes = path.as_deref().and_then(|p| read(p).ok());
    initialized(receiver, bytes, bundle, path)
}

/// `-[NSNib initWithNibData:bundle:]`: the archive is the data's bytes,
/// copied, so the caller's object can change or go away.
unsafe extern "C" fn init_with_nib_data(
    receiver: Id,
    _sel: objc::sel::Sel,
    data: Id,
    bundle: Id,
) -> Id {
    let bundle = match bundle.is_null() {
        true => main_bundle(),
        false => bundle,
    };
    let bytes = match data.is_null() {
        true => None,
        // SAFETY: an `NSData`, which is a CFData.
        false => unsafe {
            let data = data as corefoundation::base::CFTypeRef;
            let length = usize::try_from(corefoundation::api::CFDataGetLength(data)).ok();
            let start = corefoundation::api::CFDataGetBytePtr(data);
            match (length, start.is_null()) {
                (Some(0), _) => Some(Vec::new()),
                (Some(length), false) => Some(std::slice::from_raw_parts(start, length).to_vec()),
                _ => None,
            }
        },
    };
    initialized(receiver, bytes, bundle, None)
}

/// Build the receiver's nib with `owner` as File's Owner. `retained` keeps
/// the top-level objects at the extra reference the pre-10.8 method left for
/// the caller to release; the current method hands them over in the array.
fn instantiate(receiver: Id, owner: Id, top_level: *mut Id, retained: bool) -> u8 {
    if !top_level.is_null() {
        // SAFETY: the caller passed a writable `NSArray **`.
        unsafe { *top_level = std::ptr::null_mut() };
    }
    let nib = nib_of(receiver);
    if nib.bytes.is_null() {
        return 0;
    }
    // SAFETY: from `Box::into_raw`, and alive as long as the receiver is.
    let bytes = unsafe { &*nib.bytes };
    let shown = match nib.path.is_null() {
        true => PathBuf::from("<nib data>"),
        // SAFETY: as above.
        false => unsafe { (*nib.path).clone() },
    };
    let loaded = match load_bytes(bytes, owner) {
        Ok(loaded) => loaded,
        Err(why) => {
            eprintln!("rosemary: appkit: {}: {why}", shown.display());
            return 0;
        }
    };
    loaded.report(&shown);
    if !top_level.is_null() {
        // SAFETY: as above.
        unsafe { *top_level = top_level_array(&loaded, owner) };
    }
    if !retained {
        // The load retains each object it records, File's Owner aside; the
        // current method gives that reference up, so what the caller keeps is
        // what the array and the graph's own connections hold.
        for object in loaded.objects.values() {
            if !object.is_null() && *object != owner {
                objc::arc::release(*object);
            }
        }
    }
    1
}

/// `-[NSNib instantiateWithOwner:topLevelObjects:]`.
unsafe extern "C" fn instantiate_with_owner(
    receiver: Id,
    _sel: objc::sel::Sel,
    owner: Id,
    top_level: *mut Id,
) -> u8 {
    instantiate(receiver, owner, top_level, false)
}

/// `-[NSNib instantiateNibWithOwner:topLevelObjects:]`, the pre-10.8 spelling,
/// which leaves each top-level object retained for the caller.
unsafe extern "C" fn instantiate_nib_with_owner(
    receiver: Id,
    _sel: objc::sel::Sel,
    owner: Id,
    top_level: *mut Id,
) -> u8 {
    instantiate(receiver, owner, top_level, true)
}

unsafe extern "C" fn nib_dealloc(receiver: Id, _sel: objc::sel::Sel) {
    let nib = nib_of(receiver);
    if !nib.bytes.is_null() {
        // SAFETY: from `Box::into_raw`, and this is the last reference.
        drop(unsafe { Box::from_raw(nib.bytes) });
        nib.bytes = std::ptr::null_mut();
    }
    if !nib.path.is_null() {
        // SAFETY: as above.
        drop(unsafe { Box::from_raw(nib.path) });
        nib.path = std::ptr::null_mut();
    }
    objc::arc::release(nib.bundle);
    nib.bundle = std::ptr::null_mut();
    objc::arc::finalize(receiver);
}

pub(crate) fn install() {
    let nib = objc::class::lookup(c"NSNib").expect("declared in `classes`");
    methods!(nib, {
        "initWithNibNamed:bundle:" => init_with_nib_named, c"@32@0:8@16@24";
        "initWithNibData:bundle:" => init_with_nib_data, c"@32@0:8@16@24";
        "instantiateWithOwner:topLevelObjects:" => instantiate_with_owner, c"B32@0:8@16^@24";
        "instantiateNibWithOwner:topLevelObjects:" => instantiate_nib_with_owner, c"B32@0:8@16^@24";
        "dealloc" => nib_dealloc, c"v16@0:8";
    });
    let bundle = objc::class::lookup(c"NSBundle").expect("Foundation registered NSBundle");
    methods!(bundle, {
        "loadNibNamed:owner:topLevelObjects:" => load_named, c"B40@0:8@16@24^@32";
    });
    class_methods!(bundle, {
        "loadNibNamed:owner:" => load_named_class, c"c32@0:8@16@24";
    });
}

/// What a load produced.
#[derive(Debug)]
pub struct Loaded {
    /// The objects the nib built, by their place in the archive.
    pub objects: BTreeMap<Uid, Id>,
    /// Class names the nib held that nothing implements, deduplicated.
    pub placeholders: Vec<String>,
    /// Connections that were not made, each as a sentence naming why.
    pub unwired: Vec<String>,
}

impl Loaded {
    /// Print what could not be built.
    pub fn report(&self, path: &Path) {
        if !self.placeholders.is_empty() {
            eprintln!(
                "rosemary: appkit: {}: {} class(es) with no implementation: {}",
                path.display(),
                self.placeholders.len(),
                self.placeholders.join(", ")
            );
        }
        for line in &self.unwired {
            eprintln!("rosemary: appkit: {}: {line}", path.display());
        }
    }
}

/// Read the nib at `path` and wire it, with `owner` standing in for File's
/// Owner.
///
/// `path` may be a file or a `.nib` directory, which is how a modern Xcode
/// writes one. In the directory case the `keyedobjects.nib` inside it is the
/// archive; a sibling `keyedobjects-NNNNNN.nib` is the same document in the
/// `NIBArchive` format, which is a different format entirely and is not read
/// here.
pub fn load(path: &Path, owner: Id) -> Result<Loaded, String> {
    load_bytes(&read(path)?, owner)
}

/// The archive bytes of the nib at `path`, a file or a `.nib` directory.
fn read(path: &Path) -> Result<Vec<u8>, String> {
    let file = match path.is_dir() {
        true => path.join("keyedobjects.nib"),
        false => path.to_path_buf(),
    };
    std::fs::read(&file).map_err(|e| format!("{}: {e}", file.display()))
}

/// Build and wire the nib whose archive is `bytes`, with `owner` standing in
/// for File's Owner - [`load`] for a nib already in memory.
pub fn load_bytes(bytes: &[u8], owner: Id) -> Result<Loaded, String> {
    let archive = Archive::parse(bytes).map_err(|e| e.to_string())?;

    // `IB.objectdata` is where Interface Builder files the object data; `root`
    // is what an archive made any other way calls its top object. Both, because
    // a nib is only one of the two and a caller cannot tell which from outside.
    let root = archive
        .top("IB.objectdata")
        .or_else(|| archive.root())
        .ok_or("the archive names no top-level object")?;
    if !archive.is_kind_of(root, "NSIBObjectData") {
        return Err(format!(
            "the archive's top object is a {}, not an NSIBObjectData",
            archive.class_name(root).unwrap_or("<untyped entry>")
        ));
    }

    let mut builder = Builder {
        archive: &archive,
        owner,
        file_owner: archive.field_object(root, "NSRoot"),
        decoding: None,
        loaded: Loaded {
            objects: BTreeMap::new(),
            placeholders: Vec::new(),
            unwired: Vec::new(),
        },
    };
    builder.build_menus(root);
    builder.connect(root);
    builder.show_visible_windows(root);
    builder.awake();
    Ok(builder.loaded)
}

/// Whether something implements a class of this name.
///
/// Not the same question as whether one is registered: a class invented for an
/// earlier entry is registered and implements nothing, and treating it as real
/// is how a second connection to the same window template would come to be
/// wired to an object with no methods.
fn implemented(name: &str) -> bool {
    !crate::classes::is_placeholder(name)
        && std::ffi::CString::new(name)
            .ok()
            .and_then(|n| objc::class::lookup(&n))
            .is_some()
}

struct Builder<'a> {
    archive: &'a Archive,
    owner: Id,
    /// The entry [`Builder::build`] is building, so a decoder can read the rest
    /// of its fields.
    ///
    /// A field rather than an argument because `build` is reached from
    /// `instantiate` by class name alone, and threading the entry through every
    /// caller would put it in the two paths that do not need it.
    decoding: Option<Uid>,
    /// The entry the archive calls `NSRoot`, which is File's Owner: the one
    /// object a nib does not build, because the caller supplies it.
    file_owner: Option<Uid>,
    loaded: Loaded,
}

impl Builder<'_> {
    /// Walk `NSConnections` and apply each one.
    fn connect(&mut self, root: Uid) {
        let Some(connections) = self.archive.field_object(root, "NSConnections") else {
            return;
        };
        for connector in self.archive.array(connections) {
            let kind = self.archive.class_name(connector).unwrap_or_default();
            let label = self
                .archive
                .field_uid(connector, "NSLabel")
                .and_then(|l| self.archive.string(l))
                .unwrap_or_default()
                .to_string();
            let Some(source) = self.archive.field_object(connector, "NSSource") else {
                self.loaded
                    .unwired
                    .push(format!("a {kind} for \"{label}\" names no source"));
                continue;
            };
            let source_class = self
                .archive
                .class_name(source)
                .unwrap_or("<untyped entry>")
                .to_string();
            match kind {
                "NSNibOutletConnector" | "NSNibOutletConnector2" => {
                    // An outlet with no destination is an outlet set to nil,
                    // which the object already is.
                    if let Some(destination) = self.archive.field_object(connector, "NSDestination")
                    {
                        self.outlet(source, destination, &label);
                    }
                }
                "NSNibControlConnector" => {
                    let destination = self.archive.field_object(connector, "NSDestination");
                    self.action(source, destination, &label, &source_class);
                }
                other => self
                    .loaded
                    .unwired
                    .push(format!("a connector of an unknown kind, {other}")),
            }
        }
    }

    /// Build the menus the nib names for the application - its menu bar
    /// above all - which nothing else in the nib refers to.
    fn build_menus(&mut self, root: Uid) {
        let Some(objects) = self.archive.field_object(root, "NSObjectsKeys") else {
            return;
        };
        for entry in self.archive.array(objects) {
            let named = self.archive.class_name(entry) == Some("NSMenu")
                && self
                    .archive
                    .field_object(entry, "NSName")
                    .and_then(|name| self.archive.string(name))
                    .is_some_and(|name| name.starts_with("_NS"));
            if named {
                self.instantiate(entry);
            }
        }
    }

    /// `[source setTarget:destination]` and `[source setAction:label]`: a
    /// menu item's or a control's action. The first responder placeholder
    /// is a nil target, which sends the action up the responder chain.
    fn action(&mut self, source: Uid, destination: Option<Uid>, label: &str, source_class: &str) {
        let takes_action = self.instantiate(source).filter(|object| {
            // SAFETY: an object this loader built.
            unsafe { objc::object::class_of(*object) }
                .is_some_and(|c| c.method(objc::sel::get("setAction:")).is_some())
        });
        let Some(object) = takes_action else {
            self.loaded.unwired.push(format!(
                "the action \"{label}\" on a {source_class} is not connected: it takes no action"
            ));
            return;
        };
        let first_responder = destination.is_some_and(|uid| {
            self.archive.class_name(uid) == Some("NSCustomObject")
                && self.custom_class_name(uid).as_deref() == Some("FirstResponder")
        });
        let target = match (destination, first_responder) {
            (Some(uid), false) => self.instantiate(uid).unwrap_or(std::ptr::null_mut()),
            _ => std::ptr::null_mut(),
        };
        // SAFETY: `-setAction:` is `void (id, SEL, SEL)` and `-setTarget:`
        // `void (id, SEL, id)`, which is what an object that answers the first
        // has.
        unsafe {
            let set_action: unsafe extern "C" fn(Id, objc::sel::Sel, objc::sel::Sel) =
                std::mem::transmute(objc::msg::entry());
            set_action(object, objc::sel::get("setAction:"), objc::sel::get(label));
            let set_target: unsafe extern "C" fn(Id, objc::sel::Sel, Id) =
                std::mem::transmute(objc::msg::entry());
            set_target(object, objc::sel::get("setTarget:"), target);
        }
    }

    /// Order front the windows the document had open when it was saved.
    ///
    /// `NSVisibleWindows` is that set, and AppKit shows them as part of loading
    /// the nib - which is why a Cocoa program's main window appears without the
    /// program ever asking for it. Deltarune never sends
    /// `-makeKeyAndOrderFront:` to its game window: it was visible in Interface
    /// Builder, so the nib is what shows it, and a loader that skips this runs
    /// the whole game into a window nobody can see.
    fn show_visible_windows(&mut self, root: Uid) {
        let Some(windows) = self.archive.field_object(root, "NSVisibleWindows") else {
            return;
        };
        for entry in self.archive.array(windows) {
            let Some(window) = self.instantiate(entry) else {
                continue;
            };
            // SAFETY: `-makeKeyAndOrderFront:` is `void (id, SEL, id)`, which
            // every window this loader built answers.
            unsafe {
                let f: unsafe extern "C" fn(Id, objc::sel::Sel, Id) =
                    std::mem::transmute(objc::msg::entry());
                f(
                    window,
                    objc::sel::get("makeKeyAndOrderFront:"),
                    std::ptr::null_mut(),
                );
            }
        }
    }

    /// Send `-awakeFromNib` to everything the nib built, and to the owner.
    ///
    /// After every connection, and to every object. That order is AppKit's
    /// and is the whole point of the message: it is where an object does the
    /// setting-up that needs its outlets, and an object woken before its outlets
    /// were wired would find them nil.
    ///
    /// Skipping this is not a missing nicety. Deltarune's `YYGLView` creates its
    /// `NSOpenGLContext` in `-awakeFromNib`, so without it the view exists, the
    /// window exists, and the runner prints `Nil context detected` and never
    /// draws.
    ///
    /// Only objects that implement it, and the owner only if it does: Apple
    /// sends it to whatever responds, and `-[NSObject awakeFromNib]` does not
    /// exist to inherit.
    fn awake(&mut self) {
        let sel = objc::sel::get("awakeFromNib");
        let mut targets: Vec<Id> = self.loaded.objects.values().copied().collect();
        if !self.owner.is_null() && !targets.contains(&self.owner) {
            targets.push(self.owner);
        }
        for object in targets {
            // SAFETY: an object this loader built or was handed.
            let responds =
                unsafe { objc::object::class_of(object) }.is_some_and(|c| c.method(sel).is_some());
            if !responds {
                continue;
            }
            // SAFETY: `-awakeFromNib` is `void (id, SEL)`.
            unsafe {
                let f: unsafe extern "C" fn(Id, objc::sel::Sel) =
                    std::mem::transmute(objc::msg::entry());
                f(object, sel);
            }
        }
    }

    /// `[source setValue:destination forKey:label]`.
    fn outlet(&mut self, source: Uid, destination: Uid, label: &str) {
        let source_class = self
            .archive
            .class_name(source)
            .unwrap_or("<untyped entry>")
            .to_string();
        if let Some(class) = self.unimplemented(source) {
            self.loaded.unwired.push(format!(
                "the outlet \"{label}\" of a {class} is not set, because this runtime has no \
                 {class}"
            ));
            return;
        }
        let (Some(from), Some(to)) = (self.instantiate(source), self.instantiate(destination))
        else {
            self.loaded.unwired.push(format!(
                "the outlet \"{label}\" of a {source_class} has no object to set"
            ));
            return;
        };
        // SAFETY: an object this loader just built or was handed as the owner.
        let accepts = unsafe { objc::object::class_of(from) }
            .is_some_and(|c| foundation::kvc::accepts(c, label));
        if !accepts {
            let class = self.class_of(from, &source_class);
            self.loaded.unwired.push(format!(
                "the outlet \"{label}\" of a {class} is not set: it has no setValue:forKey: \
                 target of that name"
            ));
            return;
        }
        let key = foundation::string::from_str(label);
        // SAFETY: `-setValue:forKey:` is `void (id, SEL, id, id)`, installed on
        // `NSObject` by `foundation::kvc`, so every object here answers it.
        unsafe {
            let f: unsafe extern "C" fn(Id, objc::sel::Sel, Id, Id) =
                std::mem::transmute(objc::msg::entry());
            f(from, objc::sel::get("setValue:forKey:"), to, key);
        }
    }

    /// The entry's class, when nothing in this process implements it, noted in
    /// the report on the way past.
    ///
    /// `None` for the owner - the caller supplied that object, so what the nib
    /// recorded about its class is a claim about the document rather than about
    /// this process - and for a plain entry, which is a string and needs no
    /// class at all.
    fn unimplemented(&mut self, uid: Uid) -> Option<String> {
        if Some(uid) == self.file_owner {
            return None;
        }
        let name = match self.archive.class_name(uid) {
            Some("NSCustomObject") => self.custom_class_name(uid)?,
            Some(other) => other.to_string(),
            None => return None,
        };
        // A class `crate::decode` builds is implemented whatever the runtime's
        // class table says: `NSWindowTemplate` has no class of its own and
        // never will, because what it describes is an `NSWindow`.
        if implemented(&name) || crate::decode::DECODED.contains(&name.as_str()) {
            return None;
        }
        self.note(&name);
        Some(name)
    }

    /// The runtime's name for an object, falling back to what the archive
    /// called it - which is what a null or foreign pointer would leave.
    fn class_of(&self, object: Id, fallback: &str) -> String {
        // SAFETY: an object this loader built.
        unsafe { objc::object::class_of(object) }
            .map_or_else(|| fallback.to_string(), |c| c.name_str().to_string())
    }

    /// Record a class name the nib held that nothing implements, once.
    fn note(&mut self, name: &str) {
        if !self.loaded.placeholders.iter().any(|p| p == name) {
            self.loaded.placeholders.push(name.to_string());
        }
    }

    fn initialize_with_init(&self, uid: Uid) -> bool {
        match self.archive.field(uid, "NSInitializeWithInit") {
            Some(foundation::plist::Value::Bool(value)) => *value,
            Some(other) => other.as_i64().is_some_and(|value| value != 0),
            None => false,
        }
    }

    fn custom_class_name(&self, uid: Uid) -> Option<String> {
        let name = self.archive.field_uid(uid, "NSClassName")?;
        Some(self.archive.string(name)?.to_string())
    }

    /// The object for an entry, built once and remembered.
    fn instantiate(&mut self, uid: Uid) -> Option<Id> {
        if let Some(existing) = self.loaded.objects.get(&uid) {
            return Some(*existing);
        }
        if Some(uid) == self.file_owner {
            self.loaded.objects.insert(uid, self.owner);
            return Some(self.owner);
        }

        let object = match self.archive.class_name(uid) {
            // A plain entry that is a string is a string, and the archive holds
            // its text rather than an object to build.
            None => foundation::string::from_str(self.archive.string(uid)?),
            Some("NSCustomObject") => {
                let name = self.custom_class_name(uid)?;
                self.build(&name)
            }
            // A swapper of a plain object - an "Object" given a custom class in
            // Interface Builder - archives nothing but the class, and AppKit
            // makes it with `-init`. It is not a view and has no frame.
            Some("NSClassSwapper") if self.initialize_with_init(uid) => {
                let name = self.custom_class_name(uid)?;
                self.build(&name)
            }
            Some(name) => {
                let name = name.to_string();
                self.decoding = Some(uid);
                let object = self.build(&name);
                self.decoding = None;
                object
            }
        };
        objc::arc::retain(object);
        self.loaded.objects.insert(uid, object);
        Some(object)
    }

    /// An instance of `name`, or of a class invented for it.
    ///
    /// `-init` is *sent* rather than skipped for a class this process has, since
    /// a guest's delegate is entitled to have one and a nib is how it is created.
    /// An invented class has no `-init` at all, so nothing is sent to one.
    fn build(&mut self, name: &str) -> Id {
        // An archived AppKit object is not built by allocating a class of its
        // name: `NSWindowTemplate` is a *description* of an `NSWindow`, and the
        // name is the description's. `crate::decode` is where that is undone.
        if crate::decode::DECODED.contains(&name) {
            return self
                .decoding
                .take()
                .and_then(|uid| crate::decode::build(self, uid, name))
                .unwrap_or(std::ptr::null_mut());
        }
        let known = implemented(name)
            .then(|| {
                std::ffi::CString::new(name)
                    .ok()
                    .and_then(|n| objc::class::lookup(&n))
            })
            .flatten();
        let Some(class) = known else {
            self.note(name);
            let Some(class) = crate::classes::placeholder(name) else {
                return std::ptr::null_mut();
            };
            return objc::object::create_instance(class, 0);
        };
        let object = objc::object::create_instance(class, 0);
        if class.method(objc::sel::get("init")).is_some() {
            // SAFETY: `-init` is `id (id, SEL)` for every class that has one.
            unsafe {
                let f: unsafe extern "C" fn(Id, objc::sel::Sel) -> Id =
                    std::mem::transmute(objc::msg::entry());
                return f(object, objc::sel::get("init"));
            }
        }
        object
    }
}

impl crate::decode::Builder for Builder<'_> {
    fn archive(&self) -> &Archive {
        self.archive
    }

    fn object_at(&mut self, uid: Uid) -> Option<Id> {
        self.instantiate(uid)
    }

    fn note_missing(&mut self, name: &str) {
        self.note(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A nib with the one connection that matters - File's Owner's `delegate`
    /// outlet, wired to a custom object the archive names by class - and one
    /// that cannot be made, from a class nothing implements.
    ///
    /// The second source is a made-up class rather than `NSWindowTemplate`:
    /// that one *is* built now, by `crate::decode`, and building it needs a
    /// display. What this fixture is about is the reporting path, which wants a
    /// class that will never be implemented rather than one that just was.
    ///
    /// Written as the XML spelling of a keyed archive, which is what `plutil
    /// -convert xml1` makes of the binary one an Interface Builder document is,
    /// and read by the same code that reads the binary.
    const NIB: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>$archiver</key>
	<string>NSKeyedArchiver</string>
	<key>$objects</key>
	<array>
		<string>$null</string>
		<dict>
			<key>$class</key><dict><key>CF$UID</key><integer>10</integer></dict>
			<key>NSConnections</key><dict><key>CF$UID</key><integer>4</integer></dict>
			<key>NSRoot</key><dict><key>CF$UID</key><integer>2</integer></dict>
		</dict>
		<dict>
			<key>$class</key><dict><key>CF$UID</key><integer>11</integer></dict>
			<key>NSClassName</key><dict><key>CF$UID</key><integer>3</integer></dict>
		</dict>
		<string>NSApplication</string>
		<dict>
			<key>$class</key><dict><key>CF$UID</key><integer>12</integer></dict>
			<key>NS.objects</key>
			<array>
				<dict><key>CF$UID</key><integer>5</integer></dict>
				<dict><key>CF$UID</key><integer>8</integer></dict>
			</array>
		</dict>
		<dict>
			<key>$class</key><dict><key>CF$UID</key><integer>13</integer></dict>
			<key>NSSource</key><dict><key>CF$UID</key><integer>2</integer></dict>
			<key>NSDestination</key><dict><key>CF$UID</key><integer>6</integer></dict>
			<key>NSLabel</key><dict><key>CF$UID</key><integer>7</integer></dict>
		</dict>
		<dict>
			<key>$class</key><dict><key>CF$UID</key><integer>11</integer></dict>
			<key>NSClassName</key><dict><key>CF$UID</key><integer>14</integer></dict>
		</dict>
		<string>delegate</string>
		<dict>
			<key>$class</key><dict><key>CF$UID</key><integer>13</integer></dict>
			<key>NSSource</key><dict><key>CF$UID</key><integer>9</integer></dict>
			<key>NSDestination</key><dict><key>CF$UID</key><integer>2</integer></dict>
			<key>NSLabel</key><dict><key>CF$UID</key><integer>7</integer></dict>
		</dict>
		<dict>
			<key>$class</key><dict><key>CF$UID</key><integer>15</integer></dict>
		</dict>
		<dict>
			<key>$classes</key><array><string>NSIBObjectData</string></array>
			<key>$classname</key><string>NSIBObjectData</string>
		</dict>
		<dict>
			<key>$classes</key><array><string>NSCustomObject</string></array>
			<key>$classname</key><string>NSCustomObject</string>
		</dict>
		<dict>
			<key>$classes</key><array><string>NSMutableArray</string><string>NSArray</string></array>
			<key>$classname</key><string>NSMutableArray</string>
		</dict>
		<dict>
			<key>$classes</key><array><string>NSNibOutletConnector</string></array>
			<key>$classname</key><string>NSNibOutletConnector</string>
		</dict>
		<string>RosemaryTestNibDelegate</string>
		<dict>
			<key>$classes</key><array><string>RosemaryTestUnbuiltClass</string></array>
			<key>$classname</key><string>RosemaryTestUnbuiltClass</string>
		</dict>
	</array>
	<key>$top</key>
	<dict>
		<key>IB.objectdata</key><dict><key>CF$UID</key><integer>1</integer></dict>
	</dict>
	<key>$version</key>
	<integer>100000</integer>
</dict>
</plist>"#;

    /// The class the nib names as its custom object, registered so the loader
    /// finds one rather than inventing a placeholder for it.
    fn delegate_class() {
        crate::bootstrap();
        corefoundation::base::register(c"RosemaryTestNibDelegate", None, size_of::<usize>(), false);
    }

    /// A file of this test's own: the tests run in one process and in parallel,
    /// so a shared path is two of them writing the same bytes and one of them
    /// deleting the other's.
    fn write(name: &str, nib: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("rosemary-nib-{}-{name}.nib", std::process::id()));
        std::fs::write(&path, nib).expect("writable");
        path
    }

    #[test]
    fn the_owners_outlet_is_wired_to_the_object_the_nib_names() {
        delegate_class();
        let owner = objc::object::create_instance(
            objc::class::lookup(c"NSApplication").expect("NSApplication"),
            0,
        );
        let path = write("outlet", NIB);
        let loaded = load(&path, owner).expect("a nib");
        let _ = std::fs::remove_file(&path);

        // SAFETY: `-delegate` is `id (id, SEL)` on `NSApplication`.
        let delegate = unsafe {
            let f: unsafe extern "C" fn(Id, objc::sel::Sel) -> Id =
                std::mem::transmute(objc::msg::entry());
            f(owner, objc::sel::get("delegate"))
        };
        assert!(!delegate.is_null(), "the delegate outlet was not set");
        // SAFETY: a live object this runtime allocated.
        let class = unsafe { objc::object::class_of(delegate) }.expect("a class");
        assert_eq!(class.name_str(), "RosemaryTestNibDelegate");
        assert!(
            loaded
                .placeholders
                .contains(&"RosemaryTestUnbuiltClass".to_string()),
            "the class nothing implements was not reported: {:?}",
            loaded.placeholders
        );
    }

    /// The connection whose source is a class nothing implements is *named*,
    /// not silently dropped and not fatal.
    #[test]
    fn a_connection_from_an_unimplemented_class_is_reported() {
        delegate_class();
        let owner = objc::object::create_instance(
            objc::class::lookup(c"NSApplication").expect("NSApplication"),
            0,
        );
        let path = write("reported", NIB);
        let loaded = load(&path, owner).expect("a nib");
        let _ = std::fs::remove_file(&path);
        assert!(
            loaded
                .unwired
                .iter()
                .any(|u| u.contains("RosemaryTestUnbuiltClass") && u.contains("delegate")),
            "{:?}",
            loaded.unwired
        );
    }

    /// A main menu whose one item quits: named `_NSMainMenu`, with the item's
    /// action a control connection to the first responder.
    const MENU_NIB: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>$archiver</key>
	<string>NSKeyedArchiver</string>
	<key>$objects</key>
	<array>
		<string>$null</string>
		<dict>
			<key>$class</key><dict><key>CF$UID</key><integer>21</integer></dict>
			<key>NSRoot</key><dict><key>CF$UID</key><integer>2</integer></dict>
			<key>NSConnections</key><dict><key>CF$UID</key><integer>4</integer></dict>
			<key>NSObjectsKeys</key><dict><key>CF$UID</key><integer>5</integer></dict>
		</dict>
		<dict>
			<key>$class</key><dict><key>CF$UID</key><integer>22</integer></dict>
			<key>NSClassName</key><dict><key>CF$UID</key><integer>3</integer></dict>
		</dict>
		<string>NSApplication</string>
		<dict>
			<key>$class</key><dict><key>CF$UID</key><integer>23</integer></dict>
			<key>NS.objects</key><array><dict><key>CF$UID</key><integer>6</integer></dict></array>
		</dict>
		<dict>
			<key>$class</key><dict><key>CF$UID</key><integer>23</integer></dict>
			<key>NS.objects</key><array><dict><key>CF$UID</key><integer>7</integer></dict></array>
		</dict>
		<dict>
			<key>$class</key><dict><key>CF$UID</key><integer>24</integer></dict>
			<key>NSSource</key><dict><key>CF$UID</key><integer>10</integer></dict>
			<key>NSDestination</key><dict><key>CF$UID</key><integer>8</integer></dict>
			<key>NSLabel</key><dict><key>CF$UID</key><integer>9</integer></dict>
		</dict>
		<dict>
			<key>$class</key><dict><key>CF$UID</key><integer>25</integer></dict>
			<key>NSTitle</key><dict><key>CF$UID</key><integer>11</integer></dict>
			<key>NSMenuItems</key><dict><key>CF$UID</key><integer>12</integer></dict>
			<key>NSName</key><dict><key>CF$UID</key><integer>13</integer></dict>
		</dict>
		<dict>
			<key>$class</key><dict><key>CF$UID</key><integer>22</integer></dict>
			<key>NSClassName</key><dict><key>CF$UID</key><integer>14</integer></dict>
		</dict>
		<string>terminate:</string>
		<dict>
			<key>$class</key><dict><key>CF$UID</key><integer>26</integer></dict>
			<key>NSTitle</key><dict><key>CF$UID</key><integer>15</integer></dict>
			<key>NSKeyEquiv</key><dict><key>CF$UID</key><integer>16</integer></dict>
			<key>NSKeyEquivModMask</key><integer>1048576</integer>
		</dict>
		<string>Main</string>
		<dict>
			<key>$class</key><dict><key>CF$UID</key><integer>23</integer></dict>
			<key>NS.objects</key><array><dict><key>CF$UID</key><integer>17</integer></dict></array>
		</dict>
		<string>_NSMainMenu</string>
		<string>FirstResponder</string>
		<string>Quit</string>
		<string>q</string>
		<dict>
			<key>$class</key><dict><key>CF$UID</key><integer>26</integer></dict>
			<key>NSTitle</key><dict><key>CF$UID</key><integer>18</integer></dict>
			<key>NSSubmenu</key><dict><key>CF$UID</key><integer>19</integer></dict>
		</dict>
		<string>App</string>
		<dict>
			<key>$class</key><dict><key>CF$UID</key><integer>25</integer></dict>
			<key>NSTitle</key><dict><key>CF$UID</key><integer>18</integer></dict>
			<key>NSMenuItems</key><dict><key>CF$UID</key><integer>20</integer></dict>
		</dict>
		<dict>
			<key>$class</key><dict><key>CF$UID</key><integer>23</integer></dict>
			<key>NS.objects</key><array><dict><key>CF$UID</key><integer>10</integer></dict></array>
		</dict>
		<dict>
			<key>$classes</key><array><string>NSIBObjectData</string></array>
			<key>$classname</key><string>NSIBObjectData</string>
		</dict>
		<dict>
			<key>$classes</key><array><string>NSCustomObject</string></array>
			<key>$classname</key><string>NSCustomObject</string>
		</dict>
		<dict>
			<key>$classes</key><array><string>NSMutableArray</string><string>NSArray</string></array>
			<key>$classname</key><string>NSMutableArray</string>
		</dict>
		<dict>
			<key>$classes</key><array><string>NSNibControlConnector</string></array>
			<key>$classname</key><string>NSNibControlConnector</string>
		</dict>
		<dict>
			<key>$classes</key><array><string>NSMenu</string></array>
			<key>$classname</key><string>NSMenu</string>
		</dict>
		<dict>
			<key>$classes</key><array><string>NSMenuItem</string></array>
			<key>$classname</key><string>NSMenuItem</string>
		</dict>
	</array>
	<key>$top</key>
	<dict>
		<key>IB.objectdata</key><dict><key>CF$UID</key><integer>1</integer></dict>
	</dict>
	<key>$version</key>
	<integer>100000</integer>
</dict>
</plist>"#;

    /// The menu bar a main nib names becomes the application's, and its
    /// items get the actions their connections give them.
    #[test]
    fn a_nibs_main_menu_is_installed_with_its_actions() {
        crate::bootstrap();
        let class = objc::class::ptr(objc::class::lookup(c"NSApplication").expect("NSApplication"));
        // SAFETY: `+sharedApplication` is `id (Class, SEL)`.
        let app = unsafe {
            let f: unsafe extern "C" fn(Id, objc::sel::Sel) -> Id =
                std::mem::transmute(objc::msg::entry());
            f(class as Id, objc::sel::get("sharedApplication"))
        };
        let path = write("menu", MENU_NIB);
        let loaded = load(&path, app).expect("a nib");
        let _ = std::fs::remove_file(&path);
        assert!(
            !loaded.unwired.iter().any(|u| u.contains("terminate:")),
            "{:?}",
            loaded.unwired
        );

        let main = crate::menu::main_menu();
        assert!(!main.is_null(), "the nib's menu bar was not installed");
        let holders = crate::menu::shown_items(main);
        assert_eq!(holders.len(), 1);
        assert_eq!(crate::menu::display_title(holders[0]), "App");
        let items = crate::menu::shown_items(crate::menu::submenu_of(holders[0]));
        assert_eq!(items.len(), 1);
        let quit = items[0];
        assert_eq!(crate::menu::display_title(quit), "Quit");
        assert_eq!(crate::menu::shortcut_label(quit), "\u{2318}Q");
        // SAFETY: `-action` is `SEL (id, SEL)` and `-target` `id (id, SEL)`.
        unsafe {
            let action: unsafe extern "C" fn(Id, objc::sel::Sel) -> objc::sel::Sel =
                std::mem::transmute(objc::msg::entry());
            assert_eq!(
                action(quit, objc::sel::get("action")),
                objc::sel::get("terminate:")
            );
            let target: unsafe extern "C" fn(Id, objc::sel::Sel) -> Id =
                std::mem::transmute(objc::msg::entry());
            assert!(
                target(quit, objc::sel::get("target")).is_null(),
                "the first responder is a nil target"
            );
        }
    }

    /// `NSNib` holds an archive to instantiate later, as Electron loads its
    /// main menu: `-initWithNibData:bundle:` then
    /// `-instantiateWithOwner:topLevelObjects:`, which wires the owner and hands
    /// back the objects built. No data is no nib.
    #[test]
    fn an_nsnib_instantiates_the_archive_it_was_given() {
        delegate_class();
        let class = objc::class::lookup(c"NSNib").expect("NSNib");
        // SAFETY: `-initWithNibData:bundle:` is `id (id, SEL, id, id)`, and
        // `-instantiateWithOwner:topLevelObjects:` `BOOL (id, SEL, id, id *)`.
        unsafe {
            let init: unsafe extern "C" fn(Id, objc::sel::Sel, Id, Id) -> Id =
                std::mem::transmute(objc::msg::entry());
            let instantiate: unsafe extern "C" fn(Id, objc::sel::Sel, Id, *mut Id) -> u8 =
                std::mem::transmute(objc::msg::entry());
            let get: unsafe extern "C" fn(Id, objc::sel::Sel) -> Id =
                std::mem::transmute(objc::msg::entry());
            let selector = objc::sel::get("initWithNibData:bundle:");

            let empty = objc::object::create_instance(class, 0);
            assert!(init(empty, selector, std::ptr::null_mut(), std::ptr::null_mut()).is_null());

            let data = corefoundation::api::CFDataCreate(
                std::ptr::null(),
                NIB.as_ptr(),
                NIB.len() as isize,
            ) as Id;
            let nib = init(
                objc::object::create_instance(class, 0),
                selector,
                data,
                std::ptr::null_mut(),
            );
            assert!(!nib.is_null(), "a nib made from data");
            objc::arc::release(data);

            let owner = objc::object::create_instance(
                objc::class::lookup(c"NSApplication").expect("NSApplication"),
                0,
            );
            let mut top_level: Id = std::ptr::null_mut();
            let built = instantiate(
                nib,
                objc::sel::get("instantiateWithOwner:topLevelObjects:"),
                owner,
                &mut top_level,
            );
            assert_eq!(built, 1);
            assert!(!top_level.is_null(), "the top-level objects come back");
            let delegate = get(owner, objc::sel::get("delegate"));
            assert!(!delegate.is_null(), "the owner's outlet was wired");
            assert_eq!(
                objc::object::class_of(delegate)
                    .expect("a class")
                    .name_str(),
                "RosemaryTestNibDelegate"
            );
            objc::arc::release(nib);
        }
    }

    #[test]
    fn a_plist_that_is_not_a_nib_is_an_error_rather_than_a_stop() {
        crate::bootstrap();
        let path = write(
            "notanib",
            "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>\
             <key>$archiver</key><string>NSKeyedArchiver</string>\
             <key>$objects</key><array><string>$null</string></array>\
             <key>$top</key><dict><key>root</key><dict><key>CF$UID</key><integer>0</integer>\
             </dict></dict></dict></plist>",
        );
        let err = load(&path, std::ptr::null_mut()).expect_err("not a nib");
        let _ = std::fs::remove_file(&path);
        assert!(err.contains("NSIBObjectData"), "{err}");
    }
}
