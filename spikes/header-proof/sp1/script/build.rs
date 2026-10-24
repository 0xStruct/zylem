fn main() {
    for program in ["../program", "../link", "../leaf", "../agg", "../leaf-v2", "../agg-v2"] {
        sp1_build::build_program_with_args(program, Default::default());
    }
}
