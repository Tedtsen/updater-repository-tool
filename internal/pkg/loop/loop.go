package loop

type Loop struct {
	loopFunc  func()
	isRunning bool
}

func New(fun func()) *Loop {
	return &Loop{
		loopFunc: fun,
	}
}

func (l *Loop) RunRoutine(c chan int) {
	go l.run(c)
}

// Do not call this directly as it will block,
// instead call RunRoutine
func (l *Loop) run(c chan int) {
	for l.isRunning = true; l.isRunning; {
		l.loopFunc()
	}
	c <- 1
}

func (l *Loop) Kill() {
	l.isRunning = false
}
