#include <gtest/gtest.h>
#include "Math.h"

#if 0

class MathValueParameterizedTestFixture :public ::testing::TestWithParam<int> 
{
protected:
	Math<int> math;
};

TEST_P(MathValueParameterizedTestFixture, IsEven)
{
	int num = GetParam();
	ASSERT_TRUE(math.is_even(num));
}

INSTANTIATE_TEST_SUITE_P
(
	IsEvenTests,
	MathValueParameterizedTestFixture,
	::testing::Values(
		8, 20, 70, 1404
	)
);

#endif
