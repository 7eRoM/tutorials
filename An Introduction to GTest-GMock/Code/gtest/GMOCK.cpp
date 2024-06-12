#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "Math.h"
#include <utility>

#if 1

using namespace ::testing;

template <typename E>
class MockMath : public Math<E>
{
public:
	using ReturnValue = std::pair<E, E>;
	MOCK_METHOD(ReturnValue, read_from_database, (const std::string field1, const std::string field2), (override));
};


TEST(MockTest, SumFromDatabase)
{
	MockMath<int> mock_math;                              
	EXPECT_CALL(mock_math, read_from_database(_, _))
		.WillOnce(Return(std::make_pair(3, 4)));

	const int result = mock_math.sum_from_database();

	ASSERT_EQ(result, 7);
}

#endif
