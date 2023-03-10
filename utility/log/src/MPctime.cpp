#include "../inc/MPctime.h"

#include <string>
#include <utility>

#include "critical.h"
using namespace std;


static critical::mutexed<pair<time_t,string> > _s_mp_ctime_last;

///////////////////////////
string
mp_ctime (const time_t* t)
///////////////////////////
{
  char b [2048];
  string res;

  res = ctime_r (t, b);

  return res;
}


///////////////////////////
string
mp_ctime ()
///////////////////////////
{
  time_t t = time (NULL);

  _s_mp_ctime_last.lock ();

  if (t != _s_mp_ctime_last.data ().first)
  {
    _s_mp_ctime_last.data ().first = t;
    _s_mp_ctime_last.data ().second = mp_ctime (&t);
  }

  string res = _s_mp_ctime_last.data ().second;
  _s_mp_ctime_last.unlock ();
  return res;
}


////////////////////////////////////////////////////////////////////////////
int
timeval_substract (struct timeval*       result,
                   const struct timeval* x,
                   struct timeval*       y)
////////////////////////////////////////////////////////////////////////////
{
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}
