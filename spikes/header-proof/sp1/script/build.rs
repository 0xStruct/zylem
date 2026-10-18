fn main() {
    for program in ["../program", "../link", "../leaf", "../agg"] {
        sp1_build::build_program_with_args(program, Default::default());
    }
}
