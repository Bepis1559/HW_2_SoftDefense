using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurePluginHost
{
    internal interface IPlugin
    {
        string Name { get; }
        void Execute(string input);
    }
}
