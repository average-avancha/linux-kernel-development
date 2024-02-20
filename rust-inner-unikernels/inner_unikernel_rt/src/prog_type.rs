pub(crate) trait iu_prog {
    fn prog_run(&self, ctx: *const ()) -> u32;
}
