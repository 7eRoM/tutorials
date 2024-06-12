#include <gtest/gtest.h>
#include "Math.h"

#if 0

class MathTest : public ::testing::Test
{ 
protected:
	void SetUp() override
	{
		math = new Math<int>();
	}

	void TearDown() override
	{
		delete math;
	}

	Math<int> *math;
};


TEST_F(MathTest, SummationByZero)
{
	// Arrange
	int expected = 23;

	// Act
	int result = math->sum(23, 0);

	// Assert
	ASSERT_EQ(result, expected);
}

// Mul TEST
TEST_F(MathTest, MultipleByZero)
{
	// Arrange
	int expected = 0;

	// Act
	int result = math->mul(23, 0);

	// Assert
	ASSERT_EQ(result, expected);
}

#endif
