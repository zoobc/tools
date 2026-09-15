// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_COMMON_RESULT_H
#define ZOOBC_COMMON_RESULT_H

#include <stdexcept>
#include <utility>
#include "zoobc/common/error.h"

namespace zoobc {

// Result<T> type for type-safe error handling
template <typename T>
class Result {
public:
    // Constructor for success case
    Result(T value) : has_value_(true) {
        new (&storage_.value) T(std::move(value));
    }

    // Constructor for error case
    Result(Error error) : has_value_(false) {
        new (&storage_.error) Error(std::move(error));
    }

    // Copy constructor
    Result(const Result& other) : has_value_(other.has_value_) {
        if (has_value_) {
            new (&storage_.value) T(other.storage_.value);
        } else {
            new (&storage_.error) Error(other.storage_.error);
        }
    }

    // Move constructor
    Result(Result&& other) noexcept : has_value_(other.has_value_) {
        if (has_value_) {
            new (&storage_.value) T(std::move(other.storage_.value));
        } else {
            new (&storage_.error) Error(std::move(other.storage_.error));
        }
    }

    // Destructor
    ~Result() {
        if (has_value_) {
            storage_.value.~T();
        } else {
            storage_.error.~Error();
        }
    }

    // Friend swap function for copy-and-swap idiom
    // Provides strong exception guarantee by enabling safe resource exchange
    friend void swap(Result& a, Result& b) noexcept {
        using std::swap;

        if (a.has_value_ == b.has_value_) {
            // Both have same state - simple member swap
            if (a.has_value_) {
                swap(a.storage_.value, b.storage_.value);
            } else {
                swap(a.storage_.error, b.storage_.error);
            }
        } else {
            // Different states - need to carefully swap contents
            if (a.has_value_) {
                // a has value, b has error
                T temp_value(std::move(a.storage_.value));
                a.storage_.value.~T();
                new (&a.storage_.error) Error(std::move(b.storage_.error));
                b.storage_.error.~Error();
                new (&b.storage_.value) T(std::move(temp_value));
            } else {
                // a has error, b has value
                Error temp_error(std::move(a.storage_.error));
                a.storage_.error.~Error();
                new (&a.storage_.value) T(std::move(b.storage_.value));
                b.storage_.value.~T();
                new (&b.storage_.error) Error(std::move(temp_error));
            }
            swap(a.has_value_, b.has_value_);
        }
    }

    // Unified copy/move assignment using copy-and-swap idiom
    // Takes parameter by value to leverage copy elision and provide strong exception guarantee.
    // If copying throws (during parameter construction), *this remains unchanged.
    // The subsequent swap is noexcept, ensuring the operation either fully succeeds or
    // leaves the object in its original state.
    Result& operator=(Result other) noexcept {
        swap(*this, other);
        return *this;
    }

    // Check if result contains a value
    bool IsOk() const {
        return has_value_;
    }

    // Check if result contains an error
    bool IsErr() const {
        return !has_value_;
    }

    // Get value (throws if error)
    T& Value() & {
        if (!has_value_) {
            throw std::runtime_error("Attempted to access value of error result: " +
                                     storage_.error.ToString());
        }
        return storage_.value;
    }

    const T& Value() const& {
        if (!has_value_) {
            throw std::runtime_error("Attempted to access value of error result: " +
                                     storage_.error.ToString());
        }
        return storage_.value;
    }

    T&& Value() && {
        if (!has_value_) {
            throw std::runtime_error("Attempted to access value of error result: " +
                                     storage_.error.ToString());
        }
        return std::move(storage_.value);
    }

    // Get error (throws if ok)
    const Error& GetError() const {
        if (has_value_) {
            throw std::runtime_error("Attempted to access error of ok result");
        }
        return storage_.error;
    }

    // Get value or default
    T ValueOr(T default_value) const& {
        return has_value_ ? storage_.value : std::move(default_value);
    }

    T ValueOr(T default_value) && {
        return has_value_ ? std::move(storage_.value) : std::move(default_value);
    }

    // Map operation (transform value if ok)
    template <typename F>
    auto Map(F func) -> Result<decltype(func(std::declval<T>()))> {
        using U = decltype(func(std::declval<T>()));

        if (has_value_) {
            return Result<U>(func(storage_.value));
        } else {
            return Result<U>(storage_.error);
        }
    }

    // AndThen operation (chain operations)
    template <typename F>
    auto AndThen(F func) -> decltype(func(std::declval<T>())) {
        using ReturnType = decltype(func(std::declval<T>()));

        if (has_value_) {
            return func(storage_.value);
        } else {
            return ReturnType(storage_.error);
        }
    }

    // Operator bool (check if ok)
    explicit operator bool() const {
        return has_value_;
    }

private:
    union Storage {
        T value;
        Error error;

        Storage() {}
        ~Storage() {}
    } storage_;

    bool has_value_;
};

// Specialization for void
template <>
class Result<void> {
public:
    // Constructor for success case
    Result() : error_(Error::Ok()) {}

    // Constructor for error case
    Result(Error error) : error_(std::move(error)) {}

    // Check if result is ok
    bool IsOk() const {
        return error_.IsOk();
    }

    // Check if result is error
    bool IsErr() const {
        return !error_.IsOk();
    }

    // Get error
    const Error& GetError() const {
        return error_;
    }

    // Operator bool
    explicit operator bool() const {
        return IsOk();
    }

private:
    Error error_;
};

}  // namespace zoobc

#endif  // ZOOBC_COMMON_RESULT_H
