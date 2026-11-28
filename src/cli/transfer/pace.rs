//! How many connections a parallel download uses: it grows back after a run of successful
//! parts, and each time growing fails it waits longer before the next try.

/// Successful parts per connection before one more is tried.
const FIRST_PATIENCE: usize = 2;
const MOST_PATIENCE: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Pace {
    limit: usize,
    requested: usize,
    streak: usize,
    patience: usize,
    /// A connection was just added and has not proved itself yet.
    probing: bool,
}

impl Pace {
    pub(super) fn new(limit: usize, requested: usize) -> Self {
        Self {
            limit: limit.max(1),
            requested: requested.max(1),
            streak: 0,
            patience: FIRST_PATIENCE,
            probing: false,
        }
    }

    pub(super) fn limit(&self) -> usize {
        self.limit
    }

    pub(super) fn patience(&self) -> usize {
        self.patience
    }

    /// Carries what was learned about the server into the next attempt.
    pub(super) fn with_patience(mut self, patience: usize) -> Self {
        self.patience = patience.clamp(FIRST_PATIENCE, MOST_PATIENCE);
        self
    }

    /// A part arrived. Returns the new count when one more connection should start.
    pub(super) fn succeeded(&mut self) -> Option<usize> {
        self.streak += 1;
        if self.probing && self.streak >= self.limit {
            self.probing = false;
        }
        if self.limit >= self.requested || self.streak < self.limit * self.patience {
            return None;
        }
        self.limit += 1;
        self.streak = 0;
        self.probing = true;
        Some(self.limit)
    }

    /// A transient failure. When it is the connection just added that failed, returns the
    /// count without it; otherwise the normal retries handle it.
    pub(super) fn failed(&mut self) -> Option<usize> {
        self.streak = 0;
        if !self.probing {
            return None;
        }
        self.probing = false;
        self.limit = (self.limit - 1).max(1);
        self.patience = (self.patience * 2).min(MOST_PATIENCE);
        Some(self.limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(pace: &mut Pace, parts: usize) -> Option<usize> {
        (0..parts).filter_map(|_| pace.succeeded()).last()
    }

    #[test]
    fn grows_one_at_a_time_up_to_what_was_asked() {
        let mut pace = Pace::new(1, 3);
        assert_eq!(feed(&mut pace, 1), None);
        assert_eq!(feed(&mut pace, 1), Some(2));
        assert_eq!(feed(&mut pace, 4), Some(3));
        assert_eq!(feed(&mut pace, 100), None, "never beyond the request");
        assert_eq!(pace.limit(), 3);
    }

    #[test]
    fn a_failed_try_steps_back_and_waits_longer() {
        let mut pace = Pace::new(2, 8);
        assert_eq!(feed(&mut pace, 4), Some(3));
        assert_eq!(pace.failed(), Some(2));
        assert_eq!(pace.patience(), 4);
        assert_eq!(feed(&mut pace, 7), None);
        assert_eq!(feed(&mut pace, 1), Some(3));
    }

    #[test]
    fn a_failure_after_the_new_connection_settled_is_ordinary() {
        let mut pace = Pace::new(1, 4);
        feed(&mut pace, 2);
        feed(&mut pace, 2);
        assert_eq!(pace.failed(), None);
        assert_eq!(pace.limit(), 2);
    }
}
