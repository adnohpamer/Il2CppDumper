"""Generate an `il2cpp.h` header from Il2CppDumper's `dump.cs` output.

The official C# implementation in `Il2CppDumper/Outputs/StructGenerator.cs`
produces the header by combining metadata and binary information.  When only
`dump.cs` is available we can still recover a useful approximation of the
structure definitions by parsing the C# source and translating each field into
its C representation.  This script focuses on that workflow so that reversing
sessions in IDA/Ghidra/Binary Ninja can continue with typed information even
without the richer metadata that `script.json` would normally provide.

The generator intentionally favours robustness over perfect fidelity:

* Only field declarations decorated with `[FieldOffset]` are parsed.  Method
  bodies and properties are ignored.
* Field types falling outside the known primitive set are mapped back to the
  closest Il2Cpp-style name.  When the type cannot be resolved, `Il2CppObject*`
  is used as a conservative fallback.
* Arrays are represented as `Il2CppArray*`.  The original C# generator emits
  specialised array structures, however doing so requires metadata that is not
  present in `dump.cs` alone.

The script requires Python 3.9+ and can be invoked as:

```
python script/struct_gen.py --dump path/to/dump.cs --output il2cpp.h \
    --header-version 29
```

The `--header-version` flag controls which Il2Cpp runtime layout to emit.
Supported values mirror the versions in `HeaderConstants.cs` (22, 24, 24.1,
24.2, 27 and 29).  When omitted the script defaults to 29, matching modern
Unity releases.
"""

from __future__ import annotations

import argparse
import dataclasses
import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# Header templates copied from `HeaderConstants.cs`
# ---------------------------------------------------------------------------
GENERIC_HEADER = """typedef void(*Il2CppMethodPointer)();

struct MethodInfo;

struct VirtualInvokeData
{
    Il2CppMethodPointer methodPtr;
    const MethodInfo* method;
};

struct Il2CppType
{
    void* data;
    unsigned int bits;
};

struct Il2CppClass;

struct Il2CppObject
{
    Il2CppClass *klass;
    void *monitor;
};

union Il2CppRGCTXData
{
    void* rgctxDataDummy;
    const MethodInfo* method;
    const Il2CppType* type;
    Il2CppClass* klass;
};

struct Il2CppRuntimeInterfaceOffsetPair
{
    Il2CppClass* interfaceType;
    int32_t offset;
};

"""

HEADER_VARIANTS: Dict[str, str] = {
    "22": """struct Il2CppClass
{
    void* image;
    void* gc_desc;
    const char* name;
    const char* namespaze;
    Il2CppType byval_arg;
    Il2CppType this_arg;
    Il2CppClass* element_class;
    Il2CppClass* castClass;
    Il2CppClass* declaringType;
    Il2CppClass* parent;
    void *generic_class;
    void *typeDefinition;
    void *interopData;
    Il2CppClass* klass;
    void* fields;
    void* events;
    void* properties;
    void* methods;
    Il2CppClass** nestedTypes;
    Il2CppClass** implementedInterfaces;
    Il2CppRuntimeInterfaceOffsetPair* interfaceOffsets;
    int32_t cctor_started;
    uint32_t cctor_finished;
    size_t cctor_thread;
    int32_t static_fields_size;
    uint32_t instance_size;
    uint32_t actualSize;
    uint32_t element_size;
    int32_t native_size;
    uint32_t static_fields_count;
    uint32_t thread_static_fields_size;
    int32_t thread_static_fields_offset;
    uint32_t flags;
    uint32_t token;
    uint16_t method_count;
    uint16_t property_count;
    uint16_t field_count;
    uint16_t event_count;
    uint16_t nested_type_count;
    uint16_t vtable_count;
    uint16_t interfaces_count;
    uint16_t interface_offsets_count;
    uint8_t typeHierarchyDepth;
    uint8_t genericRecursionDepth;
    uint8_t rank;
    uint8_t minimumAlignment;
    uint8_t naturalAligment;
    uint8_t packingSize;
    uint8_t bitflags;
    VirtualInvokeData vtable[255];
};

typedef uintptr_t il2cpp_array_size_t;
typedef int32_t il2cpp_array_lower_bound_t;
struct Il2CppArrayBounds
{
    il2cpp_array_size_t length;
    il2cpp_array_lower_bound_t lower_bound;
};

struct Il2CppArray
{
    Il2CppClass *klass;
    void *monitor;
    void *bounds;
    il2cpp_array_size_t max_length;
    void *vector[32];
};

struct MethodInfo
{
    Il2CppMethodPointer methodPointer;
    Il2CppMethodPointer virtualMethodPointer;
    const void *invoker_method;
    const char* name;
    Il2CppClass *klass;
    const Il2CppType *return_type;
    const Il2CppType** parameters;
    const Il2CppRGCTXData* rgctx_data;
    const void* generic_method;
    uint32_t token;
    uint16_t flags;
    uint16_t iflags;
    uint16_t slot;
    uint8_t parameters_count;
    uint8_t bitflags;
};

""",
    "24": """struct Il2CppClass_1
{
    void* image;
    void* gc_desc;
    const char* name;
    const char* namespaze;
    Il2CppType byval_arg;
    Il2CppType this_arg;
    Il2CppClass* element_class;
    Il2CppClass* castClass;
    Il2CppClass* declaringType;
    Il2CppClass* parent;
    void *generic_class;
    void *typeDefinition;
    void *interopData;
    Il2CppClass* klass;
    void* fields;
    void* events;
    void* properties;
    void* methods;
    Il2CppClass** nestedTypes;
    Il2CppClass** implementedInterfaces;
    Il2CppRuntimeInterfaceOffsetPair* interfaceOffsets;
};

struct Il2CppClass_2
{
    Il2CppClass** typeHierarchy;
    void *unity_user_data;
    uint32_t initializationExceptionGCHandle;
    uint32_t cctor_started;
    uint32_t cctor_finished;
    size_t cctor_thread;
    int32_t static_fields_size;
    uint32_t instance_size;
    uint32_t actualSize;
    uint32_t element_size;
    int32_t native_size;
    uint32_t static_fields_count;
    uint32_t thread_static_fields_size;
    int32_t thread_static_fields_offset;
    uint32_t flags;
    uint32_t token;
    uint16_t method_count;
    uint16_t property_count;
    uint16_t field_count;
    uint16_t event_count;
    uint16_t nested_type_count;
    uint16_t vtable_count;
    uint16_t interfaces_count;
    uint16_t interface_offsets_count;
    uint8_t typeHierarchyDepth;
    uint8_t genericRecursionDepth;
    uint8_t rank;
    uint8_t minimumAlignment;
    uint8_t naturalAligment;
    uint8_t packingSize;
    uint8_t bitflags;
};

struct Il2CppClass
{
    Il2CppClass_1 _1;
    void* static_fields;
    const void* rgctx_data;
    Il2CppClass_2 _2;
    VirtualInvokeData vtable[255];
};

typedef uintptr_t il2cpp_array_size_t;
typedef int32_t il2cpp_array_lower_bound_t;
struct Il2CppArrayBounds
{
    il2cpp_array_size_t length;
    il2cpp_array_lower_bound_t lower_bound;
};

struct Il2CppArray
{
    Il2CppClass *klass;
    void *monitor;
    void *bounds;
    il2cpp_array_size_t max_length;
    void *vector[32];
};

struct MethodInfo
{
    Il2CppMethodPointer methodPointer;
    Il2CppMethodPointer virtualMethodPointer;
    const void *invoker_method;
    const char* name;
    Il2CppClass *klass;
    const Il2CppType *return_type;
    const Il2CppType** parameters;
    const Il2CppRGCTXData* rgctx_data;
    const void* genericMethod;
    uint32_t token;
    uint16_t flags;
    uint16_t iflags;
    uint16_t slot;
    uint8_t parameters_count;
    uint8_t bitflags;
};

""",
    "24.1": """struct Il2CppClass_1
{
    void* image;
    void* gc_desc;
    const char* name;
    const char* namespaze;
    Il2CppType byval_arg;
    Il2CppType this_arg;
    Il2CppClass* element_class;
    Il2CppClass* castClass;
    Il2CppClass* declaringType;
    Il2CppClass* parent;
    void *generic_class;
    void *typeDefinition;
    void *interopData;
    Il2CppClass* klass;
    void* fields;
    void* events;
    void* properties;
    void* methods;
    Il2CppClass** nestedTypes;
    Il2CppClass** implementedInterfaces;
    Il2CppRuntimeInterfaceOffsetPair* interfaceOffsets;
};

struct Il2CppClass_2
{
    Il2CppClass** typeHierarchy;
    void *unity_user_data;
    uint32_t initializationExceptionGCHandle;
    uint32_t cctor_started;
    uint32_t cctor_finished;
    size_t cctor_thread;
    void* genericContainerHandle;
    int32_t static_fields_size;
    uint32_t instance_size;
    uint32_t actualSize;
    uint32_t element_size;
    int32_t native_size;
    uint32_t static_fields_count;
    uint32_t thread_static_fields_size;
    int32_t thread_static_fields_offset;
    uint32_t flags;
    uint32_t token;
    uint16_t method_count;
    uint16_t property_count;
    uint16_t field_count;
    uint16_t event_count;
    uint16_t nested_type_count;
    uint16_t vtable_count;
    uint16_t interfaces_count;
    uint16_t interface_offsets_count;
    uint8_t typeHierarchyDepth;
    uint8_t genericRecursionDepth;
    uint8_t rank;
    uint8_t minimumAlignment;
    uint8_t naturalAligment;
    uint8_t packingSize;
    uint8_t bitflags;
};

struct Il2CppClass
{
    Il2CppClass_1 _1;
    void* static_fields;
    const void* rgctx_data;
    Il2CppClass_2 _2;
    VirtualInvokeData vtable[255];
};

typedef uintptr_t il2cpp_array_size_t;
typedef int32_t il2cpp_array_lower_bound_t;
struct Il2CppArrayBounds
{
    il2cpp_array_size_t length;
    il2cpp_array_lower_bound_t lower_bound;
};

struct Il2CppArray
{
    Il2CppClass *klass;
    void *monitor;
    void *bounds;
    il2cpp_array_size_t max_length;
    void *vector[32];
};

struct MethodInfo
{
    Il2CppMethodPointer methodPointer;
    Il2CppMethodPointer virtualMethodPointer;
    const void *invoker_method;
    const char* name;
    Il2CppClass *klass;
    const Il2CppType *return_type;
    const Il2CppType** parameters;
    const Il2CppRGCTXData* rgctx_data;
    const void* methodMetadataHandle;
    const void* genericMethod;
    uint32_t token;
    uint16_t flags;
    uint16_t iflags;
    uint16_t slot;
    uint8_t parameters_count;
    uint8_t bitflags;
};

""",
    "24.2": """struct Il2CppClass_1
{
    void* image;
    void* gc_desc;
    const char* name;
    const char* namespaze;
    Il2CppType byval_arg;
    Il2CppType this_arg;
    Il2CppClass* element_class;
    Il2CppClass* castClass;
    Il2CppClass* declaringType;
    Il2CppClass* parent;
    void *generic_class;
    void *typeMetadataHandle;
    void *interopData;
    Il2CppClass* klass;
    void* fields;
    void* events;
    void* properties;
    void* methods;
    Il2CppClass** nestedTypes;
    Il2CppClass** implementedInterfaces;
    Il2CppRuntimeInterfaceOffsetPair* interfaceOffsets;
};

struct Il2CppClass_2
{
    Il2CppClass** typeHierarchy;
    void *unity_user_data;
    uint32_t initializationExceptionGCHandle;
    uint32_t cctor_started;
    uint32_t cctor_finished;
    size_t cctor_thread;
    void* genericContainerHandle;
    uint32_t instance_size;
    uint32_t actualSize;
    uint32_t element_size;
    int32_t native_size;
    uint32_t static_fields_size;
    uint32_t thread_static_fields_size;
    int32_t thread_static_fields_offset;
    uint32_t flags;
    uint32_t token;
    uint16_t method_count;
    uint16_t property_count;
    uint16_t field_count;
    uint16_t event_count;
    uint16_t nested_type_count;
    uint16_t vtable_count;
    uint16_t interfaces_count;
    uint16_t interface_offsets_count;
    uint8_t typeHierarchyDepth;
    uint8_t genericRecursionDepth;
    uint8_t rank;
    uint8_t minimumAlignment;
    uint8_t naturalAligment;
    uint8_t packingSize;
    uint8_t bitflags;
};

struct Il2CppClass
{
    Il2CppClass_1 _1;
    void* static_fields;
    const void* rgctx_data;
    Il2CppClass_2 _2;
    VirtualInvokeData vtable[255];
};

typedef uintptr_t il2cpp_array_size_t;
typedef int32_t il2cpp_array_lower_bound_t;
struct Il2CppArrayBounds
{
    il2cpp_array_size_t length;
    il2cpp_array_lower_bound_t lower_bound;
};

struct Il2CppArray
{
    Il2CppClass *klass;
    void *monitor;
    void *bounds;
    il2cpp_array_size_t max_length;
    void *vector[32];
};

struct MethodInfo
{
    Il2CppMethodPointer methodPointer;
    Il2CppMethodPointer virtualMethodPointer;
    const void *invoker_method;
    const char* name;
    Il2CppClass *klass;
    const Il2CppType *return_type;
    const Il2CppType** parameters;
    const Il2CppRGCTXData* rgctx_data;
    const void* methodMetadataHandle;
    const void* genericMethod;
    uint32_t token;
    uint16_t flags;
    uint16_t iflags;
    uint16_t slot;
    uint8_t parameters_count;
    uint8_t bitflags;
};

""",
    "27": """struct Il2CppClass_1
{
    void* image;
    void* gc_desc;
    const char* name;
    const char* namespaze;
    Il2CppType byval_arg;
    Il2CppType this_arg;
    Il2CppClass* element_class;
    Il2CppClass* castClass;
    Il2CppClass* declaringType;
    Il2CppClass* parent;
    void *generic_class;
    void* typeMetadataHandle;
    void* interopData;
    Il2CppClass* klass;
    void* fields;
    void* events;
    void* properties;
    void* methods;
    Il2CppClass** nestedTypes;
    Il2CppClass** implementedInterfaces;
    Il2CppRuntimeInterfaceOffsetPair* interfaceOffsets;
};

struct Il2CppClass_2
{
    Il2CppClass** typeHierarchy;
    void *unity_user_data;
    uint32_t initializationExceptionGCHandle;
    uint32_t cctor_started;
    uint32_t cctor_finished;
    size_t cctor_thread;
    void* genericContainerHandle;
    uint32_t instance_size;
    uint32_t actualSize;
    uint32_t element_size;
    int32_t native_size;
    uint32_t static_fields_size;
    uint32_t thread_static_fields_size;
    int32_t thread_static_fields_offset;
    uint32_t flags;
    uint32_t token;
    uint16_t method_count;
    uint16_t property_count;
    uint16_t field_count;
    uint16_t event_count;
    uint16_t nested_type_count;
    uint16_t vtable_count;
    uint16_t interfaces_count;
    uint16_t interface_offsets_count;
    uint8_t typeHierarchyDepth;
    uint8_t genericRecursionDepth;
    uint8_t rank;
    uint8_t minimumAlignment;
    uint8_t naturalAligment;
    uint8_t packingSize;
    uint8_t bitflags1;
    uint8_t bitflags2;
};

struct Il2CppClass
{
    Il2CppClass_1 _1;
    void* static_fields;
    Il2CppRGCTXData* rgctx_data;
    Il2CppClass_2 _2;
    VirtualInvokeData vtable[255];
};

typedef uintptr_t il2cpp_array_size_t;
typedef int32_t il2cpp_array_lower_bound_t;
struct Il2CppArrayBounds
{
    il2cpp_array_size_t length;
    il2cpp_array_lower_bound_t lower_bound;
};

typedef void (*InvokerMethod)(Il2CppMethodPointer, const MethodInfo*, void*, void**, void*);
struct MethodInfo
{
    Il2CppMethodPointer methodPointer;
    Il2CppMethodPointer virtualMethodPointer;
    InvokerMethod invoker_method;
    const char* name;
    Il2CppClass *klass;
    const Il2CppType *return_type;
    const Il2CppType** parameters;
    union
    {
        const Il2CppRGCTXData* rgctx_data;
        const void* methodMetadataHandle;
    };
    union
    {
        const void* genericMethod;
        const void* genericContainerHandle;
    };
    uint32_t token;
    uint16_t flags;
    uint16_t iflags;
    uint16_t slot;
    uint8_t parameters_count;
    uint8_t bitflags;
};

""",
    "29": """struct Il2CppClass_1
{
    void* image;
    void* gc_desc;
    const char* name;
    const char* namespaze;
    Il2CppType byval_arg;
    Il2CppType this_arg;
    Il2CppClass* element_class;
    Il2CppClass* castClass;
    Il2CppClass* declaringType;
    Il2CppClass* parent;
    void *generic_class;
    void* typeMetadataHandle;
    void* interopData;
    Il2CppClass* klass;
    void* fields;
    void* events;
    void* properties;
    void* methods;
    Il2CppClass** nestedTypes;
    Il2CppClass** implementedInterfaces;
    Il2CppRuntimeInterfaceOffsetPair* interfaceOffsets;
};

struct Il2CppClass_2
{
    Il2CppClass** typeHierarchy;
    void *unity_user_data;
    uint32_t initializationExceptionGCHandle;
    uint32_t cctor_started;
    uint32_t cctor_finished;
    size_t cctor_thread;
    void* genericContainerHandle;
    uint32_t instance_size;
    uint32_t actualSize;
    uint32_t element_size;
    int32_t native_size;
    uint32_t static_fields_size;
    uint32_t thread_static_fields_size;
    int32_t thread_static_fields_offset;
    uint32_t flags;
    uint32_t token;
    uint16_t method_count;
    uint16_t property_count;
    uint16_t field_count;
    uint16_t event_count;
    uint16_t nested_type_count;
    uint16_t vtable_count;
    uint16_t interfaces_count;
    uint16_t interface_offsets_count;
    uint8_t typeHierarchyDepth;
    uint8_t genericRecursionDepth;
    uint8_t rank;
    uint8_t minimumAlignment;
    uint8_t naturalAligment;
    uint8_t packingSize;
    uint8_t bitflags1;
    uint8_t bitflags2;
};

struct Il2CppClass
{
    Il2CppClass_1 _1;
    void* static_fields;
    Il2CppRGCTXData* rgctx_data;
    Il2CppClass_2 _2;
    VirtualInvokeData vtable[255];
};

typedef uintptr_t il2cpp_array_size_t;
typedef int32_t il2cpp_array_lower_bound_t;
struct Il2CppArrayBounds
{
    il2cpp_array_size_t length;
    il2cpp_array_lower_bound_t lower_bound;
};

typedef void (*InvokerMethod)(Il2CppMethodPointer, const MethodInfo*, void*, void**, void*);
struct MethodInfo
{
    Il2CppMethodPointer methodPointer;
    Il2CppMethodPointer virtualMethodPointer;
    InvokerMethod invoker_method;
    const char* name;
    Il2CppClass *klass;
    const Il2CppType *return_type;
    const Il2CppType** parameters;
    union
    {
        const Il2CppRGCTXData* rgctx_data;
        const void* methodMetadataHandle;
    };
    union
    {
        const void* genericMethod;
        const void* genericContainerHandle;
    };
    uint32_t token;
    uint16_t flags;
    uint16_t iflags;
    uint16_t slot;
    uint8_t parameters_count;
    uint8_t bitflags;
};

""",
}


# ---------------------------------------------------------------------------
# Data structures used during parsing
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class Field:
    name: str
    original_type: str
    is_static: bool
    c_type: Optional[str] = None
    referenced: Optional["TypeInfo"] = None


@dataclasses.dataclass
class TypeInfo:
    full_name: str
    short_name: str
    struct_name: str
    kind: str  # "class", "struct", "enum"
    parent: Optional[str]
    enum_base: Optional[str]
    fields: List[Field]
    static_fields: List[Field]

    def is_value_type(self) -> bool:
        return self.kind in {"struct", "enum"}

    def is_enum(self) -> bool:
        return self.kind == "enum"


@dataclasses.dataclass
class Context:
    kind: str  # "namespace" or "type"
    name: str
    pop_depth: int
    type_info: Optional[TypeInfo] = None
    entered: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
MODIFIERS = {
    "public",
    "private",
    "protected",
    "internal",
    "static",
    "readonly",
    "volatile",
    "unsafe",
    "const",
    "new",
    "sealed",
    "abstract",
    "extern",
    "partial",
    "fixed",
}

PRIMITIVE_MAP = {
    "bool": "bool",
    "Boolean": "bool",
    "System.Boolean": "bool",
    "byte": "uint8_t",
    "Byte": "uint8_t",
    "System.Byte": "uint8_t",
    "sbyte": "int8_t",
    "SByte": "int8_t",
    "System.SByte": "int8_t",
    "short": "int16_t",
    "Int16": "int16_t",
    "System.Int16": "int16_t",
    "ushort": "uint16_t",
    "UInt16": "uint16_t",
    "System.UInt16": "uint16_t",
    "char": "uint16_t",
    "Char": "uint16_t",
    "System.Char": "uint16_t",
    "int": "int32_t",
    "Int32": "int32_t",
    "System.Int32": "int32_t",
    "uint": "uint32_t",
    "UInt32": "uint32_t",
    "System.UInt32": "uint32_t",
    "long": "int64_t",
    "Int64": "int64_t",
    "System.Int64": "int64_t",
    "ulong": "uint64_t",
    "UInt64": "uint64_t",
    "System.UInt64": "uint64_t",
    "float": "float",
    "Single": "float",
    "System.Single": "float",
    "double": "double",
    "Double": "double",
    "System.Double": "double",
    "string": "System_String_o*",
    "String": "System_String_o*",
    "System.String": "System_String_o*",
    "void": "void",
    "IntPtr": "intptr_t",
    "System.IntPtr": "intptr_t",
    "UIntPtr": "uintptr_t",
    "System.UIntPtr": "uintptr_t",
    "object": "Il2CppObject*",
    "Object": "Il2CppObject*",
    "System.Object": "Il2CppObject*",
}

IGNORED_BASES = {
    "object",
    "System.Object",
    "Il2CppSystem.Object",
    "ValueType",
    "System.ValueType",
}

FIELD_OFFSET_RE = re.compile(r"\[\s*FieldOffset\s*\(")
NAMESPACE_RE = re.compile(r"^namespace\s+([\w\.]+)\s*(?:\{)?\s*$")
TYPE_RE = re.compile(
    r"^(?P<prefix>(?:\[[^\]]+\]\s*)*)(?P<mods>(?:[\w]+\s+)*)"
    r"(?P<kind>class|struct|enum)\s+"
    r"(?P<name>[\w`]+(?:<[^>]+>)?)"
    r"(?:\s*:\s*(?P<bases>[^\{]+))?\s*(?:\{)?\s*$"
)


def sanitize_struct_name(name: str) -> str:
    sanitized = name.replace("::", ".")
    sanitized = sanitized.replace("+", ".")
    sanitized = sanitized.replace("/", ".")
    sanitized = sanitized.replace(" `", "`")
    sanitized = sanitized.replace("`", "_")
    sanitized = sanitized.replace("<", "_")
    sanitized = sanitized.replace(">", "")
    sanitized = sanitized.replace(",", "_")
    sanitized = sanitized.replace(" ", "_")
    sanitized = sanitized.replace("[", "_")
    sanitized = sanitized.replace("]", "")
    sanitized = sanitized.replace("-", "_")
    sanitized = sanitized.replace(":", "_")
    sanitized = sanitized.replace(".", "_")
    sanitized = re.sub(r"__+", "_", sanitized)
    if sanitized.startswith("_"):
        sanitized = sanitized[1:]
    return sanitized


IDENTIFIER_SANITIZE_RE = re.compile(r"[^0-9A-Za-z_]")


def sanitize_identifier(name: str) -> str:
    candidate = name.strip()
    if candidate.startswith("@"):  # verbatim identifier
        candidate = candidate[1:]
    candidate = candidate.replace("<", "_").replace(">", "_")
    sanitized = IDENTIFIER_SANITIZE_RE.sub("_", candidate)
    sanitized = re.sub(r"__+", "_", sanitized)
    if sanitized and sanitized[0].isdigit():
        sanitized = f"_{sanitized}"
    return sanitized or "field"


def strip_modifiers(declaration: str) -> str:
    remaining = declaration.strip()
    while True:
        parts = remaining.split(None, 1)
        if parts and parts[0] in MODIFIERS:
            if len(parts) == 1:
                return ""
            remaining = parts[1]
            continue
        break
    return remaining


def split_type_and_name(declaration: str) -> Tuple[str, str]:
    declaration = declaration.strip()
    declaration = declaration.rstrip(";")
    if "//" in declaration:
        declaration = declaration.split("//", 1)[0].rstrip()
    declaration = strip_modifiers(declaration)
    if not declaration:
        raise ValueError("Empty declaration after removing modifiers")

    depth = 0
    type_end = None
    for index, char in enumerate(declaration):
        if char == '<' or char == '[':
            depth += 1
        elif char == '>' or char == ']':
            depth = max(depth - 1, 0)
        elif char.isspace() and depth == 0:
            type_end = index
            break
    if type_end is None:
        raise ValueError(f"Cannot split declaration: {declaration}")
    type_part = declaration[:type_end]
    rest = declaration[type_end:].strip()
    name_part = rest.split('=', 1)[0].strip()
    return type_part, name_part


def normalise_type_name(name: str) -> str:
    name = name.strip()
    if name.startswith("global::"):
        name = name[len("global::"):]
    return name.replace("::", ".").replace("+", ".")


class AliasMap:
    def __init__(self) -> None:
        self._map: Dict[str, Optional[TypeInfo]] = {}

    def add(self, alias: str, info: TypeInfo) -> None:
        alias = normalise_type_name(alias)
        if alias not in self._map:
            self._map[alias] = info
            return
        existing = self._map[alias]
        if existing is info:
            return
        if existing is None:
            return
        else:
            # mark ambiguous aliases with None
            self._map[alias] = None

    def resolve(self, name: str) -> Optional[TypeInfo]:
        name = normalise_type_name(name)
        candidate = self._map.get(name)
        if candidate:
            return candidate
        # try simple name
        simple = name.split('.')[-1]
        candidate = self._map.get(simple)
        if candidate:
            return candidate
        return None


# ---------------------------------------------------------------------------
# Parsing implementation
# ---------------------------------------------------------------------------

def parse_dump(dump_path: Path) -> Tuple[List[TypeInfo], AliasMap]:
    type_infos: List[TypeInfo] = []
    alias_map = AliasMap()

    contexts: List[Context] = []
    brace_depth = 0
    pending_field = False
    current_type: Optional[TypeInfo] = None

    with dump_path.open("r", encoding="utf-8") as stream:
        for raw_line in stream:
            line = raw_line.rstrip()
            stripped = line.strip()
            open_braces = line.count('{')
            close_braces = line.count('}')
            new_depth = brace_depth + open_braces - close_braces

            namespace_match = NAMESPACE_RE.match(stripped)
            type_match = TYPE_RE.match(stripped)

            if namespace_match:
                namespace_name = namespace_match.group(1)
                block_depth = new_depth if open_braces > 0 else brace_depth + 1
                contexts.append(Context("namespace", namespace_name, block_depth, None, open_braces > 0))
            elif type_match:
                kind = type_match.group("kind")
                name = type_match.group("name")
                bases = type_match.group("bases")
                parent = None
                enum_base = None
                if bases:
                    base_candidates = [b.strip() for b in bases.split(',') if b.strip()]
                    if kind == "enum":
                        enum_base = base_candidates[0]
                    else:
                        for candidate in base_candidates:
                            if candidate in IGNORED_BASES:
                                continue
                            parent = candidate
                            break
                namespace_parts = [ctx.name for ctx in contexts if ctx.kind == "namespace"]
                type_parts = [ctx.type_info.short_name for ctx in contexts if ctx.kind == "type"]
                short_name = name
                full_name = ".".join(namespace_parts + type_parts + [short_name]) if namespace_parts or type_parts else short_name
                struct_name = sanitize_struct_name(full_name)
                type_info = TypeInfo(
                    full_name=full_name,
                    short_name=short_name,
                    struct_name=struct_name,
                    kind=kind,
                    parent=parent,
                    enum_base=enum_base,
                    fields=[],
                    static_fields=[],
                )
                type_infos.append(type_info)
                alias_map.add(full_name, type_info)
                alias_map.add(short_name, type_info)
                block_depth = new_depth if open_braces > 0 else brace_depth + 1
                contexts.append(Context("type", short_name, block_depth, type_info, open_braces > 0))
                current_type = type_info
                pending_field = False
            elif FIELD_OFFSET_RE.search(stripped):
                pending_field = True
            elif pending_field and current_type and stripped and not stripped.startswith("["):
                try:
                    type_part, name_part = split_type_and_name(stripped)
                except ValueError:
                    pending_field = False
                else:
                    is_static = " static " in f" {stripped} "
                    field = Field(
                        name=sanitize_identifier(name_part),
                        original_type=type_part,
                        is_static=is_static,
                    )
                    if is_static:
                        current_type.static_fields.append(field)
                    else:
                        current_type.fields.append(field)
                    pending_field = False

            brace_depth = new_depth
            for context in contexts:
                if not context.entered and brace_depth >= context.pop_depth:
                    context.entered = True
            while contexts and contexts[-1].entered and brace_depth < contexts[-1].pop_depth:
                popped = contexts.pop()
                if popped.kind == "type":
                    current_type = None
                    for context in reversed(contexts):
                        if context.kind == "type" and context.entered:
                            current_type = context.type_info
                            break

    return type_infos, alias_map


# ---------------------------------------------------------------------------
# Type resolution
# ---------------------------------------------------------------------------

def resolve_field_types(type_infos: Sequence[TypeInfo], alias_map: AliasMap) -> None:
    for info in type_infos:
        fields = info.fields + info.static_fields
        for field in fields:
            c_type, referenced = convert_type(field.original_type, alias_map)
            field.c_type = c_type
            field.referenced = referenced


def convert_type(original_type: str, alias_map: AliasMap) -> Tuple[str, Optional[TypeInfo]]:
    working = original_type.strip()
    pointer_suffix = ""
    while working.endswith("*"):
        pointer_suffix += "*"
        working = working[:-1].rstrip()

    array_count = 0
    while working.endswith("[]"):
        array_count += 1
        working = working[:-2].rstrip()

    nullable = working.endswith("?")
    if nullable:
        working = working[:-1]

    working = working.replace("?", "")
    working = working.strip()

    primitive = PRIMITIVE_MAP.get(working)
    if primitive:
        base = primitive
        if array_count > 0:
            base = "Il2CppArray*"
            pointer_suffix = ""
        return base + pointer_suffix, None

    referenced = alias_map.resolve(working)
    if referenced:
        if referenced.is_enum():
            base = PRIMITIVE_MAP.get(referenced.enum_base or "int32_t", "int32_t")
        elif referenced.is_value_type():
            base = f"{referenced.struct_name}_o"
        else:
            base = f"{referenced.struct_name}_o*"
        if array_count > 0:
            base = "Il2CppArray*"
            pointer_suffix = ""
        return base + pointer_suffix, referenced if referenced.is_value_type() else None

    # Fallback for generics or unresolved symbols
    if array_count > 0:
        return "Il2CppArray*", None
    if working in {"IntPtr", "System.IntPtr"}:
        return "intptr_t" + pointer_suffix, None
    return "Il2CppObject*", None


# ---------------------------------------------------------------------------
# Header rendering
# ---------------------------------------------------------------------------

def generate_header(type_infos: Sequence[TypeInfo], alias_map: AliasMap, header_version: str) -> str:
    resolve_field_types(type_infos, alias_map)

    emitted: set[str] = set()
    chunks: List[str] = []

    def emit(info: TypeInfo) -> None:
        if info.is_enum():
            return
        if info.struct_name in emitted:
            return
        # emit dependencies first
        if info.parent:
            parent_info = alias_map.resolve(info.parent)
            if parent_info:
                emit(parent_info)
        for field in info.fields + info.static_fields:
            if field.referenced:
                emit(field.referenced)
        chunks.append(render_type(info, alias_map))
        emitted.add(info.struct_name)

    for info in type_infos:
        emit(info)

    header = [GENERIC_HEADER]
    variant = HEADER_VARIANTS.get(header_version)
    if not variant:
        raise ValueError(f"Unsupported header version: {header_version}")
    header.append(variant)
    header.extend(chunks)
    return "".join(header)


def render_type(info: TypeInfo, alias_map: AliasMap) -> str:
    if not info.fields and not info.static_fields:
        # No layout information to emit.
        return ""

    parent_decl = None
    if info.parent:
        parent_info = alias_map.resolve(info.parent)
        if parent_info and not parent_info.is_enum() and parent_info.struct_name != info.struct_name:
            parent_decl = parent_info.struct_name

    lines: List[str] = []
    fields_struct_name = f"{info.struct_name}_Fields"
    if parent_decl:
        lines.append(f"struct {fields_struct_name} : {parent_decl}_Fields\n{{\n")
    else:
        lines.append(f"struct {fields_struct_name}\n{{\n")
    for field in info.fields:
        if not field.c_type:
            continue
        lines.append(f"\t{field.c_type} {field.name};\n")
    lines.append("};\n\n")

    lines.append(f"struct {info.struct_name}_c\n{{\n")
    lines.append("\tIl2CppClass_1 _1;\n")
    if info.static_fields:
        lines.append(f"\t{info.struct_name}_StaticFields* static_fields;\n")
    else:
        lines.append("\tvoid* static_fields;\n")
    lines.append("\tIl2CppRGCTXData* rgctx_data;\n")
    lines.append("\tIl2CppClass_2 _2;\n")
    lines.append("\tVirtualInvokeData vtable[32];\n")
    lines.append("};\n\n")

    lines.append(f"struct {info.struct_name}_o\n{{\n")
    if not info.is_value_type():
        lines.append(f"\t{info.struct_name}_c *klass;\n")
        lines.append("\tvoid *monitor;\n")
    lines.append(f"\t{fields_struct_name} fields;\n")
    lines.append("};\n\n")

    if info.static_fields:
        lines.append(f"struct {info.struct_name}_StaticFields\n{{\n")
        for field in info.static_fields:
            if not field.c_type:
                continue
            lines.append(f"\t{field.c_type} {field.name};\n")
        lines.append("};\n\n")

    return "".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate il2cpp.h from dump.cs")
    parser.add_argument("--dump", type=Path, default=Path("dump.cs"), help="Path to dump.cs")
    parser.add_argument("--output", type=Path, default=Path("il2cpp.h"), help="Output header path")
    parser.add_argument(
        "--header-version",
        default="29",
        choices=sorted(HEADER_VARIANTS.keys()),
        help="Header layout version to use",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> None:
    args = parse_args(argv)
    if not args.dump.exists():
        raise SystemExit(f"dump.cs not found: {args.dump}")

    type_infos, alias_map = parse_dump(args.dump)
    if not type_infos:
        raise SystemExit("No types discovered in dump.cs; is the file valid?")

    header_text = generate_header(type_infos, alias_map, args.header_version)
    args.output.write_text(header_text, encoding="utf-8")
    print(f"Generated {args.output} with {len(header_text.splitlines())} lines")


if __name__ == "__main__":
    main()
