// Writes every function IDA found, one per line ("start end name"), to
// <input file>.ida.txt next to the input, for cargo xtask measure. Run it
// with File > Script file... (Alt+F7). tools/measure/ida-export.sh runs the
// same code for many files; keep the two the same.
#include <idc.idc>

static main()
{
    auto out, ea, path, unattended;
    auto_wait();
    path = get_input_file_path() + ".ida.txt";
    out = fopen(path, "w");
    if (out == 0) {
        msg("fulg_export: cannot write %s\n", path);
        return;
    }
    fprintf(out, "# ida imagebase 0x%x\n", get_imagebase());
    ea = get_func_attr(0, FUNCATTR_START);
    if (ea != 0) {
        ea = get_next_func(0);
    }
    while (ea != BADADDR) {
        fprintf(out, "0x%x 0x%x %s\n", ea, get_func_attr(ea, FUNCATTR_END), get_func_name(ea));
        ea = get_next_func(ea);
    }
    fclose(out);
    msg("fulg_export: wrote %s\n", path);
    // -A turns batch mode on; batch() returns the old mode, put it back.
    unattended = batch(0);
    batch(unattended);
    if (unattended) {
        qexit(0);
    }
}
