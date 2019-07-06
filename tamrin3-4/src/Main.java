public class Main {
    public static void main(String[] args) {
        TestThread thread = new TestThread();
        thread.setPriority(2);
        thread.start();
    }
}
class TestThread extends Thread{
    public void run() {
        while (true) {
            try {
                super.wait(2);
            } catch (InterruptedException e) {
                System.out.println("Error");
            }
            System.out.println("oof");
        }
    }
}