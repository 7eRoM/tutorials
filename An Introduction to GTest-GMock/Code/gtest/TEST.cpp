#include <gtest/gtest.h>
#include "Math.h"

#if 0

// Sum TEST
TEST(SumTests, SummationByZero) 
{
	// Arrange
	Math<int> math;
	int expected = 23;

	// Act
	int result = math.sum(23, 0);

	// Assert
	ASSERT_EQ(result, expected);
}

TEST(SumTests, SummationSevenAndEight) 
{
	// Arrange
	Math<int> math;
	int expected = 15;

	// Act
	int result = math.sum(7, 8);

	// Assert
	ASSERT_EQ(result, expected);
}

// Mul TEST
TEST(MulTests, MultipleByZero)
{
	// Arrange
	Math<int> math;
	int expected = 0;

	// Act
	int result = math.mul(23, 0);

	// Assert
	ASSERT_EQ(result, expected);
}

TEST(MulTests, MultipleByNegative) 
{
	// Arrange
	Math<int> math;
	int expected = -23;

	// Act
	int result = math.mul(23, -1);

	// Assert
	ASSERT_EQ(result, expected);
}

#endif