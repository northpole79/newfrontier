#
# @TEST-EXEC: bro %INPUT >out 2>&1
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	print to_subnet("fe80:d04f::7aca:39ff:feb7:e472/100");
	print to_subnet("1.2.3.0/24");
	
	print to_subnet("this should fail");
	}
