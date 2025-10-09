fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc_path = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc_path);

    let proto_root = "proto";
    let proto_files = ["proto/Mumble.proto", "proto/MumbleUDP.proto"];

    for proto in &proto_files {
        println!("cargo:rerun-if-changed={proto}");
    }
    println!("cargo:rerun-if-changed={proto_root}");

    prost_build::Config::new().compile_protos(&proto_files, &[proto_root])?;
    Ok(())
}
