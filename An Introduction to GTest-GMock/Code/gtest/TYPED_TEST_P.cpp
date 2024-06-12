#include <gtest/gtest.h>
#include "Math.h"

#if 0

template <typename T>
class MathTypeParameterizedTestFixture :public ::testing::Test
{
protected:
	struct TestParams {
		T a;
		T b;
		T expected_sum;
		T expected_mul;
	};

	TestParams get_test_params()
	{
		if (std::is_same_v<T, int>)
			return TestParams{ 3, 4, 7, 12 };
		else if (std::is_same_v<T, double>)
		{
			TestParams z = { 3.0, 4.0, 7.0, 12.0 };
			return z;
		}
		else if (std::is_same_v<T, float>)
		{
			TestParams z = { 3.0f, 4.0f, 7.0f, 12.0f };
			return z;
		}
		else
			return TestParams{};
	}
};

using MyTypes = ::testing::Types<int, double, float>;

TYPED_TEST_SUITE_P(MathTypeParameterizedTestFixture);

TYPED_TEST_P(MathTypeParameterizedTestFixture, SumTest)
{
	Math<TypeParam> math;

	auto test_params = MathTypeParameterizedTestFixture<TypeParam>::get_test_params();
	TypeParam a = test_params.a;
	TypeParam b = test_params.b;
	TypeParam expected_sum = test_params.expected_sum;
	TypeParam result = a + b;
	ASSERT_EQ(result, expected_sum);
}

TYPED_TEST_P(MathTypeParameterizedTestFixture, MulTest)
{
	Math<TypeParam> math;

	auto test_params = MathTypeParameterizedTestFixture<TypeParam>::get_test_params();
	TypeParam a = test_params.a;
	TypeParam b = test_params.b;
	TypeParam expected_mul = test_params.expected_mul;
	TypeParam result = a * b;
	ASSERT_EQ(result, expected_mul);
}

REGISTER_TYPED_TEST_SUITE_P(MathTypeParameterizedTestFixture, SumTest, MulTest);

INSTANTIATE_TYPED_TEST_SUITE_P(MathTypeParameterizedTest, MathTypeParameterizedTestFixture, MyTypes);

#endif
