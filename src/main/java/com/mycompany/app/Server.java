package com.mycompany.app;

/**
 * Hello world!
 *
 */
public class Server
{
    public void bar()
    {
        System.out.println( "Hello World!" );
    }

    private void foo(String p) {
       String s = "aloha";
       System.out.println(String.format("This is a faulty message: %i", s));
       System.out.format("No %s",1);
       if ("1" == "2") {
            //dosomething
       }
    }

}
