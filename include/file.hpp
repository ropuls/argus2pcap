#pragma once

#include <cstdio>
#include <cerrno>
#include <memory>
#include <system_error>

#include <sys/stat.h>

struct file {
private:
    using deleter = int (*)(std::FILE *);
    using ftype = std::unique_ptr<FILE, deleter>;

public:
    file() :
        m_file(nullptr, ::fclose)
    {}

    file(const file &) = delete;

    file(file &&other) :
        m_file(std::move(other.m_file))
    {}

    file(const char *path, const char *mode) :
        m_file(path ? ::fopen(path, mode) : nullptr, ::fclose)
    {}

    file (const std::string &path, const char *mode, bool dothrow = false) :
        m_file(path.empty() ? nullptr : ::fopen(path.c_str(), mode), ::fclose)
    {
        if ((!m_file) && (!path.empty()) && dothrow) {
            throw std::system_error(errno, std::system_category(), path);
        }
    }

    file(FILE *f) :
        m_file(f, ::fclose)
    {}

    file &operator=(FILE *f) {
        m_file.reset(f);
        return *this;
    }

    file &operator=(const file &) = delete;

    file &operator=(file &&other) {
        if (this == &other) {
            return *this;
        }

        m_file = std::move(other.m_file);
        return *this;
    }

    void open(const char *fname, const char *mode) {
        m_file = ftype(::fopen(fname, mode), ::fclose);
    }

    void open(const std::string &fname, const char *mode) {
        return open(fname.c_str(), mode);
    }

    void close() {
        m_file = nullptr;
    }

    void rewind() {
        ::rewind(m_file.get());
    }

    void assign(int fd, const char *mode) {
        m_file.reset(fdopen(fd, mode));
    }

    int flush() {
        if (m_file) {
            return fflush(m_file.get());
        }
        errno = EINVAL;
        return EOF;
    }

    operator FILE*() {
        return m_file.get();
    }

    explicit operator bool() {
        return m_file.get() != nullptr;
    }

    size_t read(void *target, size_t count) {
        return fread(target, 1, count, m_file.get());
    }

    bool eof() {
        return (!m_file) || feof(m_file.get());
    }

    size_t write(const void *source, size_t count) {
        return fwrite(source, 1, count, m_file.get());
    }

    int fd() const {
        if (m_file) {
            return fileno(m_file.get());
        }
        return -1;
    }

    size_t size() const {
        if (m_file) {
            struct stat buf;
            if (fstat(fd(), &buf) == 0) {
                return buf.st_size;
            }
        }
        return 0;
    }

protected:
    ftype m_file;
};
