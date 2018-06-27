#!/usr/bin/env python

from z3 import *

x1 = Int('x1')
x2 = Int('x2')
x3 = Int('x3')
x4 = Int('x4')
x5 = Int('x5')
x6 = Int('x6')
x7 = Int('x7')
x8 = Int('x8')


solve(x1 < 256, x2 < 256, x3 < 256, x4 < 256, x5 < 256, x6 < 256, x7 < 256, x8 < 256, 
	(x5 + x6)*(x5 + x6) + x4*x4 == 153844, 
	(x5 + x6)*(x5 + x6) + x3*x3 == 131400, 
	x5*x5 - x1*x1 == 181,
	x6*x6 - x2*x2 == 46717,
	x1 * x4 == 19080,
	x2 * x3 == 15300,
	x1 * x5 + x1 * x6 - 119 * x5 ==	18871,
	x2 * x6 + x2 * x5 - 70 * x6 == 16930,
	x4 * x5 - x3 * x6 == -16558,
	x1 * x2 - x7 == 9043,
	x7 * x8 == 4247)

# res : 90 102 150 212 91 239 137 31

solve(x1 < 256, x2 < 256, x3 < 256, x4 < 256, x5 < 256, x6 < 256, x7 < 256, x8 < 256, 
	(x4 + x6) * (x5 + x7) + (x5 * x4) == 43907,
	x1 * x2 + x5 == 12563,
	(x1 + x6) * (x2 + x6) + x3 * x3 == 130348,
	x5 * x1 - x1 * x2 == -10682,
	x4 * x6 - x2 * x3 == -9474,
	x1 * x4 == 15484,
	x2 * x3 == 32384,
	x1 * x6 - 27 * x5 + x2 * x6 == 32257,
	x2 * x7 - 74 * x3 + x1 * x2 == 8670,
	x3 * x4 - x8 * x7 == 28838,
	x1 * x3 + x7 == 24910,
	x7 * x8 == 11136)



# res: 98 128 253 158 19 145 116 96