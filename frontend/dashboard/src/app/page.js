import Image from "next/image";
import styles from "./page.module.css";
import GraphicArea from "../../components/GraphicArea/GraphicArea";
import DiagramArea from "../../components/DiagrammArea/DiagramArea";
import RequestLogArea from "../../components/RequestLogArea/RequestLogArea";
export default function Home() {
  return (
    <div className={styles.page}>
      <h1>Network Traffic Overview</h1>
      <div className={styles.GND}> 
        <GraphicArea/>
        <DiagramArea/>
      </div>
      <RequestLogArea/>
    </div>
  );
}
