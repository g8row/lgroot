fn main() {
    slint_build::compile("ui/app.slint").expect("failed to compile ui/app.slint");
    println!("cargo:rerun-if-changed=ui/app.slint");
    println!("cargo:rerun-if-changed=assets/hbchannel.ipk");
    println!("cargo:rerun-if-changed=vendor/slopbro/wwwroot");
}
