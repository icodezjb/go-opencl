/*
 * Copyright © 2019 icodezjb
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"fmt"
	"os"

	"github.com/icodezjb/go-opencl/cl"
)

type customError struct {
	mesg string
}

func (e *customError) Error() string {
	return e.mesg
}

func fatalError(err error) {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}

const CONCURRENT_THREADS = 1
const WORKSIZE = 1
const LOOKUP_GAP = 1

func main() {
	var err error

	for _, platform := range cl.Platforms {
		for _, dev := range platform.Devices {
			var context *cl.Context
			var queue *cl.CommandQueue
			var program *cl.Program
			var kernel *cl.Kernel
			var padbuffer8 *cl.Buffer

			if context, err = cl.NewContextOfDevices(map[cl.ContextParameter]interface{}{cl.CONTEXT_PLATFORM: platform}, []cl.Device{dev}); err != nil {
				fatalError(err)
			}
			if queue, err = context.NewCommandQueue(dev, cl.QUEUE_NIL); err != nil {
				fatalError(err)
			}

			if padbuffer8, err = context.NewBuffer(cl.MEM_READ_WRITE, 128*1024+512); err != nil {
				fatalError(err)
			}

			if program, err = context.NewProgramFromFile("sipcscrypt.cl"); err != nil {
				fatalError(err)
			}

			if err = program.Build(nil,
				fmt.Sprintf(" -D LOOKUP_GAP=%d -D CONCURRENT_THREADS=%d -D WORKSIZE=%d",
					LOOKUP_GAP, CONCURRENT_THREADS, WORKSIZE)); err != nil {
				if status := program.BuildStatus(dev); status != cl.BUILD_SUCCESS {
					fatalError(&customError{fmt.Sprintf("Build Error:\n%s\n", program.Property(dev, cl.BUILD_LOG))})
				}
				fatalError(err)
			}

			if kernel, err = program.NewKernelNamed("test"); err != nil {
				fatalError(err)
			}

			if err = kernel.SetArgs(0, []interface{}{padbuffer8}); err != nil {
				fatalError(err)
			}

			if err = queue.EnqueueKernel(kernel, nil, []cl.Size{CONCURRENT_THREADS}, []cl.Size{WORKSIZE}); err != nil {
				fatalError(err)
			}

			if err := queue.Finish(); err != nil {
				fmt.Printf("Finish failed: %+v \n", err)
				return
			}

		}
	}
}
