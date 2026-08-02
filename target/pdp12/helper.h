/* SPDX-License-Identifier: GPL-2.0-or-later */

DEF_HELPER_1(tlb_flush, void, env)
DEF_HELPER_1(check_stop, void, env)
DEF_HELPER_1(retire, void, env)
DEF_HELPER_FLAGS_1(wfi, TCG_CALL_NO_RETURN, noreturn, env)
DEF_HELPER_FLAGS_2(illegal, TCG_CALL_NO_RETURN, noreturn, env, i32)
DEF_HELPER_FLAGS_3(raise_exception, TCG_CALL_NO_RETURN, noreturn,
                   env, i64, i64)
DEF_HELPER_2(rte, void, env, i32)
DEF_HELPER_3(csr_read, i64, env, i32, i32)
DEF_HELPER_4(csr_write, void, env, i32, i64, i32)
DEF_HELPER_2(validate_control_target, void, env, i64)
DEF_HELPER_3(load, i64, env, i64, i32)
DEF_HELPER_4(store, void, env, i64, i64, i32)
DEF_HELPER_4(atomic, i64, env, i64, i64, i32)
DEF_HELPER_3(div_d, i64, env, i64, i64)
DEF_HELPER_3(div_w, i64, env, i64, i64)
