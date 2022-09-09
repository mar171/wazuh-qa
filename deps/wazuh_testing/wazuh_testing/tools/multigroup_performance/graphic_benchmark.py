import numpy as np
import pandas as pd
import matplotlib.pyplot as plt



data = pd.DataFrame({'v435' : [826, 943, 942, 901],
                     'v437': [668, 781, 791, 813],
                     'v438': [488, 553, 563, 537]},
                    index=('Integrity Sync', 'Martes', 'Miercoles', 'Jueves'))

n = len(data.index)
x = np.arange(n)
width = 0.25


plt.bar(x - width, data.v435, width=width, label='v4.3.5')
plt.bar(x, data.v437, width=width, label='v4.3.7')
plt.bar(x + width, data.v438, width=width, label='v4.3.8')
plt.xticks(x, data.index)
plt.legend(loc='best')
plt.show()