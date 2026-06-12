/*
*	nettop (C) 2017-2020 E. Oriani, ema <AT> fastwebnet <DOT> it
*
*	This file is part of nettop.
*
*	nettop is free software: you can redistribute it and/or modify
*	it under the terms of the GNU General Public License as published by
*	the Free Software Foundation, either version 3 of the License, or
*	(at your option) any later version.
*
*	nettop is distributed in the hope that it will be useful,
*	but WITHOUT ANY WARRANTY; without even the implied warranty of
*	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*	GNU General Public License for more details.
*
*	You should have received a copy of the GNU General Public License
*	along with nettop.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _POLL_STDIN_
#define _POLL_STDIN_

#include <poll.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include "utils.h"

namespace utils {

	class poll_stdin {
	public:
		poll_stdin() {
		}

		// return true when need to do a refresh
		bool do_io(const size_t msec_tmout) {
			struct pollfd	pfd = {0};
			pfd.fd = STDIN_FILENO;
			pfd.events = POLLIN|POLLPRI|POLLERR;
			const int	fds = poll(&pfd, 1, msec_tmout);
			if(0 == fds)
				return false;
			else if (0 > fds) {
				if(EINTR == errno)
					return false;
				throw nettop::runtime_error("Error in poll: ") << strerror(errno);
			}
			if (pfd.revents & (POLLIN|POLLPRI|POLLERR)) {
				char		buf[128];
            			// read input line
            			const int	rb = read(STDIN_FILENO, &buf, 128);
				if(rb > 0) {
					return on_data(buf, rb);
				} else throw nettop::runtime_error("Error in reading STDIN: ") << strerror(errno);
			}
			return false;
		}

		virtual bool on_data(const char* p, const size_t sz) const = 0;

		virtual ~poll_stdin() {
		}
	};

}

#endif //_POLL_STDIN_
