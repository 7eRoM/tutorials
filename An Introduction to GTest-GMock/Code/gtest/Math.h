#pragma once

template <typename E>  // E is the element type.
class Math {
public:
	E sum(const E a, const E b);
	E sub(const E a, const E b);
	E mul(const E a, const E b);

	bool is_even(const E num);

	E sum_from_database();

protected:
	virtual std::pair<E, E> read_from_database(const std::string field1, const std::string field2);
};

template <typename E>
E Math<E>::sum(const E a, const E b)
{
	return a + b;
}

template <typename E>
E Math<E>::sub(const E a, const E b)
{
	return a - b;
}

template <typename E>
E Math<E>::mul(const E a, const E b)
{
	return a * b;
}

template <typename E>
bool Math<E>::is_even(const E num)
{
	return (num % 2 == 0);
}

template <typename E>
E Math<E>::sum_from_database()
{
	std::pair<E, E> values = read_from_database("month_!", "month_2");
	return values.first + values.second;
}

template <typename E>
std::pair<E, E> Math<E>::read_from_database(const std::string field1, const std::string field2)
{
	// Production Code. Really read from database
	return std::make_pair(1,1);
}
