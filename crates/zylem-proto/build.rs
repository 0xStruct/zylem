// Compiles the protos with protox, so building needs no protoc on the PATH.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let files = ["proto/compact_formats.proto", "proto/service.proto", "proto/zylem.proto"];
    for f in files {
        println!("cargo:rerun-if-changed={f}");
    }
    let fds = protox::compile(files, ["proto"])?;
    let grpc = std::env::var_os("CARGO_FEATURE_GRPC").is_some();
    tonic_prost_build::configure()
        .build_client(grpc)
        .build_server(grpc)
        .compile_fds(fds)?;
    Ok(())
}
