use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::shared::{json_text, package_path};

const ENCODING_PROFILE: &str = "packed-fixed-v0-reference";

#[derive(Clone)]
struct TypeInfo {
    size: usize,
    encoding: String,
}

#[derive(Clone)]
struct ParsedField {
    name: String,
    ty: String,
    line: usize,
}

fn sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn primitive_types() -> BTreeMap<String, TypeInfo> {
    [
        ("u8", 1, "little-endian unsigned integer"),
        ("u16", 2, "little-endian unsigned integer"),
        ("u32", 4, "little-endian unsigned integer"),
        ("u64", 8, "little-endian unsigned integer"),
        ("Byte32", 32, "exactly 32 bytes"),
        ("OutPoint", 36, "CKB OutPoint: tx_hash Byte32 || index u32 little-endian"),
    ]
    .into_iter()
    .map(|(name, size, encoding)| (name.to_owned(), TypeInfo { size, encoding: encoding.to_owned() }))
    .collect()
}

fn parse_types(default_type: Option<&str>, path: &Path, text: &str) -> Result<Vec<(String, Vec<ParsedField>)>> {
    let field_re = Regex::new(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z][A-Za-z0-9_]*)\b")?;
    let type_re = Regex::new(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*$")?;
    let mut current = default_type.map(str::to_owned);
    let mut fields = Vec::new();
    let mut types = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let stripped = line.split('#').next().unwrap_or_default().trim();
        if stripped.is_empty() {
            continue;
        }
        if let Some(captures) = type_re.captures(stripped) {
            if let Some(name) = current.take() {
                types.push((name, std::mem::take(&mut fields)));
            }
            current = Some(captures[1].to_owned());
            continue;
        }
        let Some(captures) = field_re.captures(stripped) else {
            bail!("unsupported schema syntax in {}:{line_number}: {line}", path.display());
        };
        if current.is_none() {
            bail!("schema file {}:{line_number} must declare TypeName: before fields", path.display());
        }
        fields.push(ParsedField { name: captures[1].to_owned(), ty: captures[2].to_owned(), line: line_number });
    }
    if let Some(name) = current {
        types.push((name, fields));
    }
    Ok(types)
}

fn components(name: &str, ty: &str, offset: usize) -> Value {
    if ty != "OutPoint" {
        return json!([]);
    }
    json!([
        {
            "name": format!("{name}.tx_hash"),
            "type": "Byte32",
            "offset": offset,
            "size_bytes": 32,
            "encoding": "exactly 32 bytes"
        },
        {
            "name": format!("{name}.index"),
            "type": "u32",
            "offset": offset + 32,
            "size_bytes": 4,
            "encoding": "little-endian unsigned integer"
        }
    ])
}

fn layout_type(
    type_name: &str,
    display_path: &Path,
    source: &[u8],
    parsed: &[ParsedField],
    known: &BTreeMap<String, TypeInfo>,
) -> Result<Value> {
    let mut offset = 0_usize;
    let mut fields = Vec::new();
    for field in parsed {
        let info = known
            .get(&field.ty)
            .with_context(|| format!("unsupported field type in {}:{}: {}", display_path.display(), field.line, field.ty))?;
        let mut row = Map::new();
        row.insert("name".into(), json!(field.name));
        row.insert("type".into(), json!(field.ty));
        row.insert("offset".into(), json!(offset));
        row.insert("size_bytes".into(), json!(info.size));
        row.insert("end_offset_exclusive".into(), json!(offset + info.size));
        row.insert("encoding".into(), json!(info.encoding));
        row.insert("source_line".into(), json!(field.line));
        let components = components(&field.name, &field.ty, offset);
        if !components.as_array().unwrap().is_empty() {
            row.insert("components".into(), components);
        }
        fields.push(Value::Object(row));
        offset += info.size;
    }
    Ok(json!({
        "name": type_name,
        "schema_path": display_path.to_string_lossy().replace('\\', "/"),
        "schema_sha256": sha256(source),
        "encoding": ENCODING_PROFILE,
        "integer_endianness": "little",
        "padding": "none",
        "dynamic_fields": false,
        "field_count": fields.len(),
        "total_static_size_bytes": offset,
        "fields": fields
    }))
}

fn build(package_root: &Path) -> Result<Value> {
    let sources = [
        (Some("NovaSealCellV0"), PathBuf::from("schemas/nova_seal_cell_v0.schema")),
        (None, PathBuf::from("schemas/nova_intent_v0.schema")),
        (None, PathBuf::from("schemas/proof_receipt_v0.schema")),
    ];
    let mut known = primitive_types();
    let mut types = Vec::new();
    for (default_type, relative) in sources {
        let bytes = fs::read(package_root.join(&relative)).with_context(|| format!("missing schema file: {}", relative.display()))?;
        let text = String::from_utf8(bytes.clone())?;
        for (type_name, parsed) in parse_types(default_type, &relative, &text)? {
            let ty = layout_type(&type_name, &relative, &bytes, &parsed, &known)?;
            known.insert(
                type_name,
                TypeInfo {
                    size: ty["total_static_size_bytes"].as_u64().unwrap() as usize,
                    encoding: format!("packed {}", ty["name"].as_str().unwrap()),
                },
            );
            types.push(ty);
        }
    }
    let fingerprint_types = types
        .iter()
        .map(|ty| {
            json!({
                "name": ty["name"],
                "total_static_size_bytes": ty["total_static_size_bytes"],
                "fields": ty["fields"].as_array().unwrap().iter().map(|field| json!({
                    "name": field["name"],
                    "type": field["type"],
                    "offset": field["offset"],
                    "size_bytes": field["size_bytes"]
                })).collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    let fingerprint = serde_json::to_vec(&json!({ "encoding_profile": ENCODING_PROFILE, "types": fingerprint_types }))?;
    Ok(json!({
        "schema": "novaseal-schema-layout-v0.1",
        "encoding_profile": ENCODING_PROFILE,
        "molecule_status": "not_generated",
        "molecule_note": "This is a packed fixed-layout reference. It is not a Molecule table/schema compiler output.",
        "outpoint_encoding": "tx_hash Byte32 || index u32 little-endian",
        "integer_endianness": "little",
        "padding": "none",
        "layout_fingerprint_sha256": sha256(&fingerprint),
        "types": types,
        "fiber_fungible_profile": {
            "status": "not_defined_in_v0_layout",
            "amount_offset": Value::Null,
            "note": "The xUDT/Fiber amount profile remains a future documented profile, not a field in NovaSealCellV0."
        },
        "limitations": [
            "No dynamic Molecule table offsets are emitted.",
            "No canonical byte vectors are produced in this slice.",
            "No CellScript compiler ABI comparison is performed here."
        ]
    }))
}

pub fn run(root: &Path, output: Option<&Path>, pretty: bool) -> Result<i32> {
    let package_root = root.join("v0-mvp-skeleton");
    let output = package_path(root, output.unwrap_or(Path::new("target/novaseal-schema-layout.json")));
    let layout = build(&package_root)?;
    fs::create_dir_all(output.parent().context("output path has no parent")?)?;
    fs::write(&output, json_text(&layout, pretty)?)?;
    let display = output.strip_prefix(&package_root).unwrap_or(&output);
    println!("wrote {}", display.display());
    for ty in layout["types"].as_array().unwrap() {
        println!(
            "{}: fields={} size={} bytes",
            ty["name"].as_str().unwrap(),
            ty["field_count"].as_u64().unwrap(),
            ty["total_static_size_bytes"].as_u64().unwrap()
        );
    }
    println!("layout_fingerprint_sha256={}", layout["layout_fingerprint_sha256"].as_str().unwrap());
    Ok(0)
}
