// Ref: https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0042/

var classSet = new Set()

setTimeout(function(){
    Java.perform(function (className) {
        // console.log("it is running!!!");
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                // console.log(className);
                if (classSet.has(className)) {
                  return;
                }
                describeJavaClass(className);
            },
            onComplete: function() {}
        });
    });

    function describeJavaClass(className) {
        var jClass = Java.use(className);
        
        // console.log(JSON.stringify({
        //   _name: className,
        //   _methods: Object.getOwnPropertyNames(jClass.__proto__).filter(m => {
        //     return !m.startsWith('$') // filter out Frida related special properties
        //        || m == 'class' || m == 'constructor' // optional
        //   }), 
        //   _fields: jClass.class.getFields().map(f => {
        //     return f.toString()
        //   })  
        // }, null, 2));

        classSet.add(className)
        var message = JSON.stringify({
          _name: className,
          _methods: Object.getOwnPropertyNames(jClass.__proto__).filter(m => {
            return !m.startsWith('$') // filter out Frida related special properties
               || m == 'class' || m == 'constructor' // optional
          }), 
          _fields: jClass.class.getFields().map(f => {
            return f.toString()
          })  
        }, null, 2);
        send(message);
      }

}, 0);
