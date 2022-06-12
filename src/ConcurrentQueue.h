#ifndef PTRACER_CONCURRENTQUEUE_H
#define PTRACER_CONCURRENTQUEUE_H

#include <queue>
#include <boost/thread.hpp>

template <typename Data>
class ConcurrentQueue {
public:
	void push(const Data data) {
		boost::mutex::scoped_lock lock(mutex);
		this->queue.push(data);
		lock.unlock();
		condition_variable.notify_one();
	}

	bool try_pop(Data& popped_value) {
		boost::mutex::scoped_lock lock(mutex);
		if (queue.empty()) {
			return false;
		}
		popped_value = queue.front();
		queue.pop();
		return true;
	}

	Data pop() {
		boost::mutex::scoped_lock lock(mutex);
		while (queue.empty()) {
			condition_variable.wait(lock);
		}
		Data popped_value = queue.front();
		queue.pop();
		return popped_value;
	}

	int size() const {
		boost::mutex::scoped_lock lock(mutex);
		return this->queue.size();
	}

	bool empty() const {
		boost::mutex::scoped_lock lock(mutex);
		return this->queue.empty();
	}

private:
	std::queue<Data> queue;
	mutable boost::mutex mutex;
	boost::condition_variable condition_variable;
};

#endif //PTRACER_CONCURRENTQUEUE_H
