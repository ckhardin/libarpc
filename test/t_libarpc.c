#include <atf-c.h>

extern void test_xdr_ops(void);
extern bool arpc_test1(void);

ATF_TC(test_arpc_ops);
ATF_TC_HEAD(test_arpc_ops, tc)
{
	atf_tc_set_md_var(tc, "descr", "test case for libarpc_ops");
}

ATF_TC_BODY(test_arpc_ops, tc)
{
	ATF_CHECK(arpc_test1() == 0);
}

ATF_TC(test_xdr_ops);
ATF_TC_HEAD(test_xdr_ops, tc)
{
	atf_tc_set_md_var(tc, "descr", "test case for libarpc xdr ops");
}
ATF_TC_BODY(test_xdr_ops, tc)
{
	test_xdr_ops();
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, test_xdr_ops);
 	ATF_TP_ADD_TC(tp, test_arpc_ops);
	return atf_no_error();
}
