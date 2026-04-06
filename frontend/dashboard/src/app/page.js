'use client';

import { useState, useEffect } from "react";
import styles from "./page.module.css";
import DiagramArea from "../../components/DiagrammArea/DiagramArea";
import InfoArea from "../../components/InfoArea/InfoArea";
import RequestLogArea from "../../components/RequestLogArea/RequestLogArea";
import DragAndDrop from "../../components/DragAndDrop/DragAndDrop";

export default function Home() {
  return (
    <DragAndDrop/>
  )
}