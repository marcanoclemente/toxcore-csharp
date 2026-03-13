using System;

namespace Toxcore.Core
{
    /// <summary>
    /// Comparador personalizado para MergeSort (sort.h).
    /// </summary>
    /// <typeparam name="T">Tipo de elemento.</typeparam>
    /// <param name="a">Primer elemento.</param>
    /// <param name="b">Segundo elemento.</param>
    /// <returns>true si a &lt; b.</returns>
    public delegate bool LessThanCallback<T>(T a, T b);

    /// <summary>
    /// Implementación de Merge Sort no recursivo con insertion sort para arrays pequeños.
    /// Traducción fiel de sort.c.
    /// 
    /// Usa O(n) espacio temporal (buffer pre-allocated).
    /// </summary>
    public static class Sort
    {
        private const int SmallArrayThreshold = 16;

        /// <summary>
        /// Ordena array usando merge sort (bottom-up).
        /// </summary>
        public static void MergeSort<T>(T[] arr, int arrSize, LessThanCallback<T> lessThan)
        {
            if (arrSize <= 1) return;

            // Buffer temporal
            var tmp = new T[arrSize];
            MergeSortWithBuffer(arr, arrSize, tmp, lessThan);
        }

        private static void MergeSortWithBuffer<T>(T[] arr, int arrSize, T[] tmp, LessThanCallback<T> lessThan)
        {
            if (arrSize <= SmallArrayThreshold)
            {
                InsertionSortWithBuffer(arr, arrSize, tmp, lessThan);
                return;
            }

            // Merge sort bottom-up
            for (int currSize = 1; currSize <= arrSize - 1; currSize *= 2)
            {
                for (int leftStart = 0; leftStart < arrSize - 1; leftStart += 2 * currSize)
                {
                    int mid = Math.Min(leftStart + currSize - 1, arrSize - 1);
                    int rightEnd = Math.Min(leftStart + 2 * currSize - 1, arrSize - 1);

                    Merge(arr, leftStart, mid, rightEnd, tmp, lessThan);
                }
            }
        }

        private static void Merge<T>(T[] arr, int leftStart, int mid, int rightEnd, T[] tmp, LessThanCallback<T> lessThan)
        {
            int leftSize = mid - leftStart + 1;
            int rightSize = rightEnd - mid;

            // Copiar a buffer temporal
            Array.Copy(arr, leftStart, tmp, 0, leftSize);
            Array.Copy(arr, mid + 1, tmp, leftSize, rightSize);

            int i = 0, j = leftSize, k = leftStart;

            while (i < leftSize && j < leftSize + rightSize)
            {
                // !(tmp[j] < tmp[i]) es equivalente a tmp[i] <= tmp[j]
                if (!lessThan(tmp[j], tmp[i]))
                {
                    arr[k] = tmp[i];
                    i++;
                }
                else
                {
                    arr[k] = tmp[j];
                    j++;
                }
                k++;
            }

            // Copiar restantes
            while (i < leftSize)
            {
                arr[k] = tmp[i];
                i++;
                k++;
            }
            while (j < leftSize + rightSize)
            {
                arr[k] = tmp[j];
                j++;
                k++;
            }
        }

        private static void InsertionSortWithBuffer<T>(T[] arr, int arrSize, T[] tmp, LessThanCallback<T> lessThan)
        {
            for (int i = 1; i < arrSize; i++)
            {
                tmp[0] = arr[i];
                int j = i;

                while (j > 0 && lessThan(tmp[0], arr[j - 1]))
                {
                    arr[j] = arr[j - 1];
                    j--;
                }
                arr[j] = tmp[0];
            }
        }

        /// <summary>
        /// Búsqueda binaria simple (utilidad adicional no en sort.c pero útil).
        /// </summary>
        public static int BinarySearch<T>(T[] arr, int length, T target, LessThanCallback<T> lessThan)
        {
            int left = 0, right = length - 1;
            while (left <= right)
            {
                int mid = left + (right - left) / 2;
                if (!lessThan(arr[mid], target) && !lessThan(target, arr[mid]))
                    return mid;
                if (lessThan(arr[mid], target))
                    left = mid + 1;
                else
                    right = mid - 1;
            }
            return -1;
        }
    }
}